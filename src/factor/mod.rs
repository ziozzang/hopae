//! Second-factor primitives. Enrollment, durable replay fencing and session integration remain separate.
pub mod enrollment;
pub mod external;
pub mod external_service;
pub mod external_transport;
pub mod keyring;
pub mod seed_cipher;
pub mod service;
pub mod totp;
