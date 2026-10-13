use std::io;
#[cfg(feature = "gssapi")]
use std::sync::RwLock;
#[cfg(feature = "gssapi")]
use std::sync::{Arc, Mutex};

use crate::RequestId;
use crate::controls::{Control, RawControl};
use crate::controls_impl::{build_tag, parse_controls};
use crate::search::SearchItem;

use lber::common::TagClass;
use lber::parse::parse_uint;
use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Integer, Sequence, Tag};
use lber::universal::Types;
use lber::write;

use bytes::{Buf, BytesMut};
#[cfg(feature = "gssapi")]
use cross_krb5::{ClientCtx, K5Ctx};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct LdapCodec {
    #[cfg(feature = "gssapi")]
    pub(crate) has_decoded_data: bool,
    #[cfg(feature = "gssapi")]
    pub(crate) sasl_param: Arc<RwLock<(bool, u32)>>, // sasl_wrap, sasl_max_send
    #[cfg(feature = "gssapi")]
    pub(crate) client_ctx: Arc<Mutex<Option<ClientCtx>>>,
}

pub(crate) type MaybeControls = Option<Vec<RawControl>>;
pub(crate) type ItemSender = mpsc::UnboundedSender<(SearchItem, Vec<Control>)>;
pub(crate) type ResultSender = oneshot::Sender<(Tag, Vec<Control>)>;

#[derive(Debug)]
pub enum MiscSender {
    #[cfg(any(feature = "tls-native", feature = "tls-rustls"))]
    Cert(oneshot::Sender<Option<Vec<u8>>>),
}

#[derive(Debug)]
pub enum LdapOp {
    Single,
    Search(ItemSender),
    Abandon(RequestId),
    Unbind,
}

// Hopae local hardening: fixed wire limit for credential-only LDAP operations.
const MAX_LDAP_FRAME: usize = 64 * 1024;

fn bounded_frame_length(buf: &[u8]) -> io::Result<Option<usize>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or oversized LDAP frame",
        )
    };
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] != 0x30 {
        return Err(invalid());
    }
    if buf.len() < 2 {
        return Ok(None);
    }
    let (header, payload) = if buf[1] < 128 {
        (2usize, usize::from(buf[1]))
    } else {
        let octets = usize::from(buf[1] & 0x7f);
        // LDAP forbids indefinite lengths; lengths wider than u32 exceed our cap.
        if octets == 0 || octets > 4 {
            return Err(invalid());
        }
        if buf.len() < 2 + octets {
            return Ok(None);
        }
        let mut payload = 0usize;
        for byte in &buf[2..2 + octets] {
            payload = payload
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
                .ok_or_else(invalid)?;
        }
        (2 + octets, payload)
    };
    let total = header.checked_add(payload).ok_or_else(invalid)?;
    if total > MAX_LDAP_FRAME {
        return Err(invalid());
    }
    Ok((buf.len() >= total).then_some(total))
}

// Iterative preflight: never recurse or allocate according to untrusted lengths.
fn validate_ber_tree(frame: &[u8]) -> io::Result<()> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or excessive LDAP BER structure",
        )
    };
    let mut ends = [frame.len(); 32];
    let mut depth = 1usize;
    let mut cursor = 0usize;
    let mut nodes = 0usize;
    while depth > 0 {
        let boundary = ends[depth - 1];
        if cursor == boundary {
            depth -= 1;
            continue;
        }
        if cursor > boundary {
            return Err(invalid());
        }
        nodes += 1;
        if nodes > 4096 {
            return Err(invalid());
        }
        let tag = *frame.get(cursor).ok_or_else(invalid)?;
        cursor += 1;
        if tag & 0x1f == 0x1f {
            let mut octets = 0;
            loop {
                if cursor >= boundary {
                    return Err(invalid());
                }
                let byte = frame[cursor];
                cursor += 1;
                octets += 1;
                if octets > 8 {
                    return Err(invalid());
                }
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        if cursor >= boundary {
            return Err(invalid());
        }
        let first = frame[cursor];
        cursor += 1;
        let length = if first < 128 {
            usize::from(first)
        } else {
            let octets = usize::from(first & 0x7f);
            if octets == 0 || octets > 4 || boundary - cursor < octets {
                return Err(invalid());
            }
            let mut value = 0usize;
            for byte in &frame[cursor..cursor + octets] {
                value = value
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(*byte)))
                    .ok_or_else(invalid)?;
            }
            cursor += octets;
            value
        };
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= boundary)
            .ok_or_else(invalid)?;
        if tag & 0x20 != 0 && length != 0 {
            if depth == ends.len() {
                return Err(invalid());
            }
            ends[depth] = end;
            depth += 1;
        } else {
            cursor = end;
        }
    }
    Ok(())
}

#[cfg(test)]
mod hopae_frame_tests {
    use super::*;
    #[test]
    fn rejects_oversized_header_without_waiting_for_payload() {
        assert!(bounded_frame_length(&[0x30, 0x83, 0x01, 0x00, 0x00]).is_err());
        assert!(bounded_frame_length(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(bounded_frame_length(&[0x30, 0x80]).is_err());
        assert!(bounded_frame_length(&[0x31, 0x01]).is_err());
    }
    #[test]
    fn fragmented_and_coalesced_frames_have_bounded_length() {
        assert_eq!(bounded_frame_length(&[]).unwrap(), None);
        assert_eq!(bounded_frame_length(&[0x30]).unwrap(), None);
        assert_eq!(bounded_frame_length(&[0x30, 0x82, 0x01]).unwrap(), None);
        assert_eq!(bounded_frame_length(&[0x30, 0x01]).unwrap(), None);
        assert_eq!(
            bounded_frame_length(&[0x30, 0x01, 0, 0x30, 0]).unwrap(),
            Some(3)
        );
        let mut maximum = vec![0; MAX_LDAP_FRAME];
        maximum[..4].copy_from_slice(&[0x30, 0x82, 0xff, 0xfc]);
        assert_eq!(
            bounded_frame_length(&maximum).unwrap(),
            Some(MAX_LDAP_FRAME)
        );
    }
    #[test]
    fn bounds_nested_depth_nodes_and_parent_lengths() {
        fn wrap(payload: Vec<u8>) -> Vec<u8> {
            let mut out = vec![0x30, 0x82, (payload.len() >> 8) as u8, payload.len() as u8];
            out.extend(payload);
            out
        }
        let mut shallow = vec![0x04, 0];
        for _ in 0..8 {
            shallow = wrap(shallow);
        }
        assert!(validate_ber_tree(&shallow).is_ok());
        let mut deep = shallow;
        for _ in 0..64 {
            deep = wrap(deep);
        }
        assert!(validate_ber_tree(&deep).is_err());
        assert!(validate_ber_tree(&wrap(vec![0x04, 0].repeat(4096))).is_err());
        assert!(validate_ber_tree(&[0x30, 2, 0x04, 5]).is_err());
        assert!(validate_ber_tree(&[0x30, 2, 0x30, 0x80]).is_err());
        assert!(validate_ber_tree(&[0x30, 1, 0x04]).is_err());
        assert!(validate_ber_tree(&[0x30, 0]).is_ok());
    }
    fn tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 128);
        let mut out = vec![tag, payload.len() as u8];
        out.extend(payload);
        out
    }
    fn message(op: Vec<u8>, extra: Vec<u8>) -> Vec<u8> {
        let mut body = vec![2, 1, 1];
        body.extend(op);
        body.extend(extra);
        tlv(0x30, &body)
    }
    fn result(op: u8) -> Vec<u8> {
        tlv(op, &[10, 1, 0, 4, 0, 4, 0])
    }
    #[test]
    fn semantic_gate_refuses_incomplete_fields_types_utf8_and_controls_without_panics() {
        let mut bad = vec![
            vec![0x30, 0],
            tlv(0x30, &[2, 1, 1]),
            message(tlv(0x61, &[]), vec![]),
            message(tlv(0x61, &[10, 0, 4, 0, 4, 0]), vec![]),
            message(tlv(0x61, &[10, 1, 255, 4, 0, 4, 0]), vec![]),
            message(tlv(0x61, &[10, 1, 0, 4, 1, 255, 4, 0]), vec![]),
            message(tlv(0x61, &[10, 1, 0, 4, 0, 4, 0, 0x83, 0]), vec![]),
            message(tlv(0x64, &[4, 0, 0x30, 2, 0x30, 0]), vec![]),
        ];
        for id in [
            vec![4, 1, 1],
            vec![2, 0],
            vec![2, 1, 255],
            vec![2, 5, 0, 0, 0, 0, 1],
        ] {
            let mut body = id;
            body.extend(result(0x61));
            bad.push(tlv(0x30, &body));
        }
        for control in [
            vec![],
            vec![4, 1, 255],
            vec![4, 0, 1, 0],
            vec![4, 0, 1, 2, 0, 0],
            vec![4, 0, 0x24, 0],
            vec![4, 0, 4, 0, 4, 0],
        ] {
            bad.push(message(result(0x61), tlv(0xa0, &tlv(0x30, &control))));
        }
        for packet in bad {
            let outcome =
                std::panic::catch_unwind(|| decode_inner(&mut BytesMut::from(packet.as_slice())));
            assert!(outcome.is_ok(), "wire decoder panicked");
            assert!(outcome.unwrap().is_err());
        }
    }
    #[test]
    fn valid_results_binary_entries_refs_controls_and_ad_notice_remain_supported() {
        let control = tlv(
            0xa0,
            &tlv(0x30, &[4, 3, b'1', b'.', b'2', 1, 1, 255, 4, 1, 255]),
        );
        for packet in [
            message(result(0x61), control),
            message(result(0x65), vec![]),
            message(result(0x78), tlv(0x8a, b"1.2.3")),
            message(tlv(0x73, &tlv(4, b"ldaps://example.test")), vec![]),
            message(
                tlv(
                    0x64,
                    &[4, 0, 0x30, 10, 0x30, 8, 4, 1, b'a', 0x31, 3, 4, 1, 255],
                ),
                vec![],
            ),
        ] {
            let (id, (tag, _)) = decode_inner(&mut BytesMut::from(packet.as_slice()))
                .unwrap()
                .unwrap();
            assert_eq!(id, 1);
            if single_response(&tag) || matches!(&tag,Tag::StructureTag(t)if t.id==5) {
                let _: crate::result::LdapResultExt = tag.into();
            } else if let Tag::StructureTag(t) = tag {
                if t.id == 4 {
                    let entry = crate::SearchEntry::construct(crate::ResultEntry(t, vec![]));
                    assert_eq!(entry.bin_attrs["a"], vec![vec![255]]);
                } else {
                    assert_eq!(crate::search::parse_refs(t).len(), 1);
                }
            }
        }
    }
    #[test]
    fn deterministic_wire_mutations_never_expose_panicking_result_or_entry_shapes() {
        let packets = [
            message(result(0x61), vec![]),
            message(
                tlv(
                    0x64,
                    &[4, 0, 0x30, 10, 0x30, 8, 4, 1, b'a', 0x31, 3, 4, 1, 255],
                ),
                vec![],
            ),
        ];
        for packet in packets {
            for position in 0..packet.len() {
                for byte in [0, 1, 16, 127, 128, 255] {
                    let mut mutated = packet.clone();
                    mutated[position] = byte;
                    let outcome = std::panic::catch_unwind(|| {
                        if let Ok(Some((_, (tag, _)))) =
                            decode_inner(&mut BytesMut::from(mutated.as_slice()))
                        {
                            if single_response(&tag)
                                || matches!(&tag,Tag::StructureTag(t)if t.id==5)
                            {
                                let _: crate::result::LdapResultExt = tag.into();
                            } else if let Tag::StructureTag(t) = tag {
                                if t.id == 4 {
                                    crate::SearchEntry::construct(crate::ResultEntry(t, vec![]));
                                } else {
                                    crate::search::parse_refs(t);
                                }
                            }
                        }
                    });
                    assert!(outcome.is_ok(), "mutation exposed a parser panic");
                }
            }
        }
    }
}

// Credential-scope semantic gate: downstream upstream parsers use infallible
// conversions. Validate their exact response shapes before exposing any tag.
fn semantic_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid LDAP response structure",
    )
}
fn children(t: &StructureTag, class: TagClass, id: u64) -> io::Result<&[StructureTag]> {
    if t.class != class || t.id != id {
        return Err(semantic_error());
    }
    match &t.payload {
        PL::C(values) => Ok(values),
        _ => Err(semantic_error()),
    }
}
fn primitive(t: &StructureTag, class: TagClass, id: u64) -> io::Result<&[u8]> {
    if t.class != class || t.id != id {
        return Err(semantic_error());
    }
    match &t.payload {
        PL::P(value) => Ok(value),
        _ => Err(semantic_error()),
    }
}
fn text(t: &StructureTag, class: TagClass, id: u64) -> io::Result<()> {
    std::str::from_utf8(primitive(t, class, id)?)
        .map(|_| ())
        .map_err(|_| semantic_error())
}
fn unsigned(t: &StructureTag, id: u64, max: u64) -> io::Result<()> {
    let bytes = primitive(t, TagClass::Universal, id)?;
    if bytes.is_empty() || bytes.len() > 4 || bytes[0] & 0x80 != 0 {
        return Err(semantic_error());
    }
    let (_, value) = parse_uint(bytes).map_err(|_| semantic_error())?;
    if value > max {
        return Err(semantic_error());
    }
    Ok(())
}
fn referrals(t: &StructureTag, class: TagClass, id: u64) -> io::Result<()> {
    let values = children(t, class, id)?;
    if values.is_empty() {
        return Err(semantic_error());
    }
    for value in values {
        text(value, TagClass::Universal, 4)?;
    }
    Ok(())
}
fn controls(t: &StructureTag) -> io::Result<()> {
    for control in children(t, TagClass::Context, 0)? {
        let fields = children(control, TagClass::Universal, 16)?;
        if fields.is_empty() || fields.len() > 3 {
            return Err(semantic_error());
        }
        text(&fields[0], TagClass::Universal, 4)?;
        let mut next = 1;
        if fields.get(next).is_some_and(|t| t.id == 1) {
            if primitive(&fields[next], TagClass::Universal, 1)?.len() != 1 {
                return Err(semantic_error());
            }
            next += 1;
        }
        if let Some(value) = fields.get(next) {
            primitive(value, TagClass::Universal, 4)?;
            next += 1;
        }
        if next != fields.len() {
            return Err(semantic_error());
        }
    }
    Ok(())
}
pub(crate) fn expected_single_response(tag: &Tag) -> Option<u64> {
    let (class, id) = match tag {
        Tag::Sequence(t) => (t.class, t.id),
        Tag::StructureTag(t) => (t.class, t.id),
        _ => return None,
    };
    if class != TagClass::Application {
        return None;
    }
    match id {
        0 => Some(1),
        6 => Some(7),
        8 => Some(9),
        10 => Some(11),
        12 => Some(13),
        14 => Some(15),
        23 => Some(24),
        _ => None,
    }
}
pub(crate) fn single_response(tag: &Tag) -> bool {
    matches!(tag,Tag::StructureTag(t) if t.class==TagClass::Application && matches!(t.id,1|7|9|11|13|15|24))
}
fn validate_response(t: &StructureTag) -> io::Result<()> {
    let outer = children(t, TagClass::Universal, 16)?;
    if !(2..=3).contains(&outer.len()) {
        return Err(semantic_error());
    }
    unsigned(&outer[0], 2, i32::MAX as u64)?;
    let op = &outer[1];
    let fields = children(op, TagClass::Application, op.id)?;
    match op.id {
        1 | 5 | 7 | 9 | 11 | 13 | 15 | 24 => {
            if fields.len() < 3 {
                return Err(semantic_error());
            }
            unsigned(&fields[0], 10, u32::MAX as u64)?;
            text(&fields[1], TagClass::Universal, 4)?;
            text(&fields[2], TagClass::Universal, 4)?;
            let mut seen = 0u16;
            for field in &fields[3..] {
                if field.class != TagClass::Context || field.id > 11 || seen & (1 << field.id) != 0
                {
                    return Err(semantic_error());
                }
                seen |= 1 << field.id;
                match field.id {
                    3 => referrals(field, TagClass::Context, 3)?,
                    7 if op.id == 1 => {
                        primitive(field, TagClass::Context, 7)?;
                    }
                    10 if op.id == 24 => text(field, TagClass::Context, 10)?,
                    11 if op.id == 24 => {
                        primitive(field, TagClass::Context, 11)?;
                    }
                    _ => return Err(semantic_error()),
                }
            }
        }
        4 => {
            if fields.len() != 2 {
                return Err(semantic_error());
            }
            text(&fields[0], TagClass::Universal, 4)?;
            for attribute in children(&fields[1], TagClass::Universal, 16)? {
                let parts = children(attribute, TagClass::Universal, 16)?;
                if parts.len() != 2 {
                    return Err(semantic_error());
                }
                text(&parts[0], TagClass::Universal, 4)?;
                for value in children(&parts[1], TagClass::Universal, 17)? {
                    primitive(value, TagClass::Universal, 4)?;
                }
            }
        }
        19 => referrals(op, TagClass::Application, 19)?,
        _ => return Err(semantic_error()),
    }
    if let Some(extra) = outer.get(2) {
        if extra.class == TagClass::Context && extra.id == 10 && op.id == 24 {
            // Preserve the upstream AD disconnection-OID workaround.
            text(extra, TagClass::Context, 10)?;
        } else {
            controls(extra)?;
        }
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
fn decode_inner(buf: &mut BytesMut) -> Result<Option<(RequestId, (Tag, Vec<Control>))>, io::Error> {
    // Bound the declared frame before lber parses or clones nested values.
    let Some(frame_length) = bounded_frame_length(buf)? else {
        return Ok(None);
    };
    validate_ber_tree(&buf[..frame_length])?;
    let decoding_error = io::Error::new(io::ErrorKind::Other, "decoding error");
    let mut parser = lber::Parser::new();
    let binding = parser.parse(buf);
    let (i, tag) = match binding {
        Err(e) if e.is_incomplete() => return Ok(None),
        Err(_e) => return Err(decoding_error),
        Ok((i, ref tag)) => (i, tag),
    };
    validate_response(tag)?;
    buf.advance(buf.len() - i.len());
    let tag = tag.clone();
    let mut tags = match tag
        .match_id(Types::Sequence as u64)
        .and_then(|t| t.expect_constructed())
    {
        Some(tags) => tags,
        None => return Err(decoding_error),
    };
    let mut maybe_controls = tags.pop().expect("element");
    let has_controls = match maybe_controls {
        StructureTag {
            id,
            class,
            ref payload,
        } if class == TagClass::Context && id == 0 => match *payload {
            PL::C(_) => true,
            PL::P(_) => return Err(decoding_error),
        },
        StructureTag { id, class, .. } if class == TagClass::Context && id == 10 => {
            // Active Directory bug workaround
            //
            // AD incorrectly encodes Notice of Disconnection messages. The OID of the
            // Unsolicited Notification should be part of the ExtendedResponse sequence
            // but AD puts it outside, where the optional controls belong. This confuses
            // our parser, which doesn't expect the extra sequence element at the end
            // and crashes. This match arm thus ignores the element.
            maybe_controls = tags.pop().expect("element");
            false
        }
        _ => false,
    };
    let (protoop, controls) = if has_controls {
        (tags.pop().expect("element"), Some(maybe_controls))
    } else {
        (maybe_controls, None)
    };
    let controls = match controls {
        Some(controls) => parse_controls(controls),
        None => vec![],
    };
    let msgid = match parse_uint(
        tags.pop()
            .expect("element")
            .match_class(TagClass::Universal)
            .and_then(|t| t.match_id(Types::Integer as u64))
            .and_then(|t| t.expect_primitive())
            .expect("message id")
            .as_slice(),
    ) {
        Ok((_, id)) => id as i32,
        _ => return Err(decoding_error),
    };
    Ok(Some((msgid, (Tag::StructureTag(protoop), controls))))
}

impl Decoder for LdapCodec {
    type Item = (RequestId, (Tag, Vec<Control>));
    type Error = io::Error;

    #[cfg(not(feature = "gssapi"))]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        decode_inner(buf)
    }

    #[cfg(feature = "gssapi")]
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();

        let sasl_wrap = { self.sasl_param.read().expect("sasl param").0 };
        if !sasl_wrap || buf.is_empty() {
            return decode_inner(buf);
        }
        if self.has_decoded_data {
            let res = decode_inner(buf);
            if res.is_ok() && buf.is_empty() {
                self.has_decoded_data = false;
            }
            return res;
        }
        if buf.len() < U32_SIZE {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid SASL buffer"));
        }
        let sasl_len = u32::from_be_bytes(buf[0..U32_SIZE].try_into().unwrap());
        if buf.len() - U32_SIZE < sasl_len as usize {
            return Ok(None);
        }
        buf.advance(U32_SIZE);
        let client_opt = &mut *self.client_ctx.lock().expect("client ctx lock");
        let client_ctx = client_opt.as_mut().expect("client Option mut ref");
        let mut decoded = client_ctx.unwrap_iov(sasl_len as usize, buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("gss_unwrap error: {:#}", e))
        })?;
        let res = decode_inner(&mut decoded);
        if res.is_ok() && !decoded.is_empty() && buf.is_empty() {
            buf.extend(decoded);
            self.has_decoded_data = true;
        }
        res
    }
}

#[cfg(not(feature = "gssapi"))]
#[inline]
fn maybe_wrap(
    _codec: &mut LdapCodec,
    outstruct: StructureTag,
    into: &mut BytesMut,
) -> io::Result<()> {
    write::encode_into(into, outstruct)?;
    Ok(())
}

#[cfg(feature = "gssapi")]
fn maybe_wrap(
    codec: &mut LdapCodec,
    outstruct: StructureTag,
    into: &mut BytesMut,
) -> io::Result<()> {
    let mut out_buf = BytesMut::new();
    write::encode_into(&mut out_buf, outstruct)?;
    let (sasl_wrap, sasl_send_max) = {
        let sasl_param = codec.sasl_param.read().expect("sasl param");
        (sasl_param.0, sasl_param.1)
    };
    if sasl_wrap {
        let client_opt = &mut *codec.client_ctx.lock().expect("client_ctx lock");
        let client_ctx = client_opt.as_mut().expect("client Option mut ref");
        if sasl_send_max > 0 && out_buf.len() > sasl_send_max as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "buffer too large for GSSAPI: {} > {}",
                    out_buf.len(),
                    sasl_send_max
                ),
            ));
        }
        let sasl_buf = client_ctx.wrap(true, &out_buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("gss_wrap error: {:#}", e))
        })?;
        let sasl_len = (sasl_buf.len() as u32).to_be_bytes();
        into.extend(&sasl_len);
        into.extend(&*sasl_buf);
    } else {
        into.extend(&out_buf);
    }
    Ok(())
}

impl Encoder<(RequestId, Tag, MaybeControls)> for LdapCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        msg: (RequestId, Tag, MaybeControls),
        into: &mut BytesMut,
    ) -> io::Result<()> {
        let (id, tag, controls) = msg;
        let outstruct = {
            let mut msg = vec![
                Tag::Integer(Integer {
                    inner: id as i64,
                    ..Default::default()
                }),
                tag,
            ];
            if let Some(controls) = controls {
                msg.push(Tag::StructureTag(StructureTag {
                    id: 0,
                    class: TagClass::Context,
                    payload: PL::C(controls.into_iter().map(build_tag).collect()),
                }));
            }
            Tag::Sequence(Sequence {
                inner: msg,
                ..Default::default()
            })
            .into_structure()
        };
        maybe_wrap(self, outstruct, into)?;
        Ok(())
    }
}
