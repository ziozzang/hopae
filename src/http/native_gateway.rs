//! Bounded loopback transport into the existing HTTP verify router/engine.
use crate::{
    app::{CallerKeys, KeyVerdict},
    gateway::{hangang, native_codec as wire},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderName, HeaderValue, Request},
};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tower::ServiceExt;
async fn read_frame(stream: &mut TcpStream) -> io::Result<(u64, Vec<u8>)> {
    let mut h = [0; 16];
    stream.read_exact(&mut h).await?;
    let (id, n) = wire::parse_header(h)?;
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes).await?;
    Ok((id, bytes))
}
async fn write_frame(stream: &mut TcpStream, id: u64, bytes: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(16 + bytes.len());
    out.extend_from_slice(&wire::frame_header(id, bytes.len())?);
    out.extend_from_slice(bytes);
    stream.write_all(&out).await
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid native verify exchange")
}
async fn connection(
    mut stream: TcpStream,
    router: Router,
    keys: Arc<CallerKeys>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let (id, key) = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut stream))
        .await
        .map_err(|_| invalid())??;
    if id != 0 || key.is_empty() || key.len() > 4096 {
        return Err(invalid());
    }
    if !matches!(keys.check(Some(&key)), KeyVerdict::Accepted(_)) {
        write_frame(&mut stream, 0, &[0]).await?;
        return Err(invalid());
    }
    let key = HeaderValue::from_bytes(&key).map_err(|_| invalid())?;
    write_frame(&mut stream, 0, &[1]).await?;
    let mut last = 0;
    loop {
        let frame = tokio::select! {_=stop.wait_for(|v|*v)=>return Ok(()),r=tokio::time::timeout(Duration::from_secs(30),read_frame(&mut stream))=>r.map_err(|_|invalid())??};
        let (id, bytes) = frame;
        if id == 0 || id <= last {
            return Err(invalid());
        }
        last = id;
        let mut headers = HeaderMap::new();
        for (name, value) in wire::decode_request(&bytes)? {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
            if name == "x-hopae-gateway-key" {
                return Err(invalid());
            }
            let value = HeaderValue::from_bytes(&value).map_err(|_| invalid())?;
            headers.append(name, value);
        }
        headers.insert("x-hopae-gateway-key", key.clone());
        // Re-enter the one authoritative caller/parse/verify/render pipeline. Its
        // key check remains current even after the transport handshake.
        let mut request = Request::builder()
            .method("GET")
            .uri(hangang::VERIFY_PATH)
            .body(Body::empty())
            .map_err(|_| invalid())?;
        *request.headers_mut() = headers;
        let response = tokio::select! {_=stop.wait_for(|v|*v)=>return Ok(()),r=router.clone().oneshot(request)=>r.map_err(|_|invalid())?};
        let (status, headers, body) = {
            let (parts, body) = response.into_parts();
            let headers = parts
                .headers
                .iter()
                .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
                .collect();
            let body = to_bytes(body, wire::MAX_BODY)
                .await
                .map_err(|_| invalid())?
                .to_vec();
            (parts.status.as_u16(), headers, body)
        };
        let reply = wire::encode_reply(&wire::Reply {
            status,
            headers,
            body,
        })?;
        tokio::select! {_=stop.wait_for(|v|*v)=>return Ok(()),r=tokio::time::timeout(Duration::from_secs(5),write_frame(&mut stream,id,&reply))=>r.map_err(|_|invalid())??};
    }
}
pub async fn serve(
    listener: TcpListener,
    router: Router,
    keys: Arc<CallerKeys>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(256));
    let mut tasks = JoinSet::new();
    let connections_stop = stop.clone();
    loop {
        tokio::select! {
         _=stop.wait_for(|v|*v)=>break,
         Some(_)=tasks.join_next()=>{},
         accepted=listener.accept()=>{let(stream,_)=accepted?;let Ok(permit)=slots.clone().try_acquire_owned()else{continue;};let router=router.clone();let keys=keys.clone();let stop=connections_stop.clone();tasks.spawn(async move{let _permit=permit;let _=connection(stream,router,keys,stop).await;});}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
