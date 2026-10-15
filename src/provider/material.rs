//! Private keyed fingerprint of the exact immutable material a compiler consumed.
//! Not an authentication capability and never exposed in a response.
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;
pub(crate) struct Key(Zeroizing<[u8; 32]>);
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fingerprint([u8; 32]);
impl Fingerprint {
    pub(crate) fn bytes(&self) -> [u8; 32] {
        self.0
    }
}
pub(crate) struct Builder(Hmac<Sha256>);
impl Key {
    /// Optional additive qualifier. Read the dedicated reference exactly once.
    pub(crate) fn resolve(
        name: Option<&str>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Option<Self> {
        let encoded = Zeroizing::new(env(name?)?);
        if encoded.len() != 43 {
            return None;
        }
        let decoded = Zeroizing::new(
            data_encoding::BASE64URL_NOPAD
                .decode(encoded.as_bytes())
                .ok()?,
        );
        let bytes = <[u8; 32]>::try_from(&decoded[..]).ok()?;
        if bytes.iter().all(|b| *b == 0)
            || data_encoding::BASE64URL_NOPAD.encode(&bytes) != *encoded
        {
            return None;
        }
        Some(Self(Zeroizing::new(bytes)))
    }
    pub(crate) fn start(&self, row: &crate::store::ProviderRow) -> Option<Builder> {
        let mut builder = Builder(Hmac::<Sha256>::new_from_slice(&self.0[..]).ok()?);
        builder.part(b"domain", b"hopae/native-compiled-provider-material/v1");
        // Presentation/order/timestamps are excluded; actual authority policy
        // and references remain bound in addition to the consumed values.
        let material = serde_json::json!({"provider_id":row.provider_id.as_str(),"kind":row.kind.as_str(),"config":row.config,"client_secret_env":row.client_secret_env,"allowed_email_domains":row.allowed_email_domains,"authoritative_domains":row.authoritative_domains,"auto_link":row.auto_link,"trust_email":row.trust_email});
        builder.part(b"authority", &serde_json::to_vec(&material).ok()?);
        Some(builder)
    }
}
impl Builder {
    pub(crate) fn part(&mut self, name: &[u8], value: &[u8]) {
        self.0.update(&(name.len() as u64).to_be_bytes());
        self.0.update(name);
        self.0.update(&(value.len() as u64).to_be_bytes());
        self.0.update(value);
    }
    pub(crate) fn finish(self) -> Fingerprint {
        Fingerprint(self.0.finalize().into_bytes().into())
    }
}
