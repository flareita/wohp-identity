use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use wohp_api::{CanonicalPerson, Error};

/// Managed key; no Debug/Display implementation. Never embed it in source/config.
pub struct LookupKey(hmac::Key);

impl LookupKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, bytes)))
    }

    pub fn generate_bytes() -> Result<[u8; 32], Error> {
        random_bytes()
    }

    pub(crate) fn identity(&self) -> Vec<u8> {
        hmac::sign(&self.0, b"wohp.lookup-key-check.v1")
            .as_ref()
            .to_vec()
    }

    pub(crate) fn person_lookup(&self, person: &CanonicalPerson) -> Vec<u8> {
        let mut context = hmac::Context::with_key(&self.0);
        context.update(b"wohp.person-reference.v1");
        // Length-prefixed UTF-8 fields: canonical and unambiguous. Policy version
        // is deliberately NOT in the identity namespace.
        for field in [person.namespace(), person.reference()] {
            context.update(&(field.len() as u64).to_be_bytes());
            context.update(field.as_bytes());
        }
        context.sign().as_ref().to_vec()
    }
}

fn random_bytes() -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Random)?;
    Ok(bytes)
}

pub(crate) fn random_token() -> Result<String, Error> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes()?))
}
