//! Envelope encryption for secrets at rest.
//!
//! Every secret is sealed with its own random 256-bit data key (DEK) using
//! AES-256-GCM. The DEK is itself encrypted ("wrapped") under a key-encryption
//! key (KEK) from the [`Keyring`]. Rotating a KEK therefore only rewraps the
//! 32-byte DEKs; the secrets are never re-encrypted.
//!
//! # Format
//!
//! - `ciphertext = nonce(12) || AES-256-GCM(DEK, plaintext, aad)`
//! - `wrapped_dek = nonce(12) || AES-256-GCM(KEK, DEK, "axon-dek:" + kek_id)`
//!
//! The caller's `aad` (for example the secret's row id and column) binds a
//! ciphertext to its place, so it cannot be moved to another row. The KEK id is
//! bound into the wrapped key the same way. Nonces are random and fresh on
//! every call.
//!
//! # Configuration
//!
//! `AXON_KEK_FILE` (a path) wins over `AXON_KEK` (the text itself). The text
//! has one KEK per non-empty line that does not start with `#`, either
//! `<id>:<secret>` or just `<secret>`. A secret has at least 32 characters
//! (`pwgen -s 64 1` works). The 32-byte key is HKDF-SHA256 of the secret. A
//! line without an id gets `k` plus the first 8 hex characters of the SHA-256
//! of the derived key. The first line is the active KEK; later lines only
//! decrypt.
//!
//! # Rotation
//!
//! 1. Put the new KEK on the first line and keep the old one below it.
//! 2. Restart and run a rewrap of every sealed secret ([`Keyring::rewrap`]).
//! 3. Drop the old line once nothing refers to its id any more.

use std::collections::HashMap;
use std::fmt;

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

/// Environment variable holding the path of the KEK file.
const ENV_KEK_FILE: &str = "AXON_KEK_FILE";
/// Environment variable holding the KEK text itself.
const ENV_KEK: &str = "AXON_KEK";

const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MIN_SECRET_LEN: usize = 32;
const MAX_ID_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"axon-gateway kek v1";
const HKDF_INFO: &[u8] = b"kek";
const DEK_AAD_PREFIX: &[u8] = b"axon-dek:";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("cannot read the KEK file {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("no KEK found: the key text has no usable line")]
    NoKeys,
    #[error("KEK line {line}: the secret must be at least {MIN_SECRET_LEN} characters")]
    ShortSecret { line: usize },
    #[error("KEK line {line}: the id must match [A-Za-z0-9._-]{{1,{MAX_ID_LEN}}}")]
    BadId { line: usize },
    #[error("KEK id {0:?} appears more than once")]
    DuplicateId(String),
    #[error("the KEK {0:?} that sealed this secret is not in the keyring (was it dropped?)")]
    UnknownKek(String),
    #[error("decryption failed: wrong key, wrong aad or damaged data")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("the system random number generator failed")]
    Random,
}

/// A secret sealed under a per-secret data key, itself wrapped by a KEK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub kek_id: String,
    pub wrapped_dek: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// The KEKs the gateway knows: one active (seals) and any number of older ones
/// (open only).
pub struct Keyring {
    active: String,
    keys: HashMap<String, [u8; KEY_LEN]>,
}

impl fmt::Debug for Keyring {
    /// Prints the ids only, never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ids: Vec<&String> = self.keys.keys().collect();
        ids.sort();
        f.debug_struct("Keyring")
            .field("active", &self.active)
            .field("ids", &ids)
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// `AXON_KEK_FILE` (path) wins over `AXON_KEK` (the text itself); `Ok(None)`
    /// when neither is set or empty.
    pub fn from_env() -> Result<Option<Self>, CryptoError> {
        let file = std::env::var(ENV_KEK_FILE).ok();
        let inline = std::env::var(ENV_KEK).ok();
        Self::from_sources(file.as_deref(), inline.as_deref())
    }

    fn from_sources(file: Option<&str>, inline: Option<&str>) -> Result<Option<Self>, CryptoError> {
        if let Some(path) = file.map(str::trim).filter(|p| !p.is_empty()) {
            let text = std::fs::read_to_string(path).map_err(|source| CryptoError::ReadFile {
                path: path.to_owned(),
                source,
            })?;
            return Self::from_text(&text).map(Some);
        }
        match inline.filter(|t| !t.trim().is_empty()) {
            Some(text) => Self::from_text(text).map(Some),
            None => Ok(None),
        }
    }

    /// Parses the KEK text; the first line is the active KEK.
    pub fn from_text(text: &str) -> Result<Self, CryptoError> {
        let mut active: Option<String> = None;
        let mut keys: HashMap<String, [u8; KEY_LEN]> = HashMap::new();

        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let number = index + 1;
            let (id, secret) = match line.split_once(':') {
                Some((id, secret)) => {
                    if !valid_id(id) {
                        return Err(CryptoError::BadId { line: number });
                    }
                    (Some(id), secret)
                }
                None => (None, line),
            };
            if secret.chars().count() < MIN_SECRET_LEN {
                return Err(CryptoError::ShortSecret { line: number });
            }
            let key = derive_kek(secret)?;
            let id = id.map_or_else(|| auto_id(&key), str::to_owned);
            if keys.contains_key(&id) {
                return Err(CryptoError::DuplicateId(id));
            }
            if active.is_none() {
                active = Some(id.clone());
            }
            keys.insert(id, key);
        }

        let active = active.ok_or(CryptoError::NoKeys)?;
        Ok(Self { active, keys })
    }

    /// The id of the key new secrets are sealed with
    #[cfg(test)]
    pub fn active_id(&self) -> &str {
        &self.active
    }

    /// Encrypts `plaintext` under a fresh data key wrapped by the active KEK.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
        let kek = self.key(&self.active)?;
        let mut dek = [0_u8; KEY_LEN];
        SystemRandom::new()
            .fill(&mut dek)
            .map_err(|_| CryptoError::Random)?;
        let ciphertext = encrypt(&dek, plaintext, aad)?;
        let wrapped_dek = encrypt(kek, &dek, &dek_aad(&self.active))?;
        Ok(Sealed {
            kek_id: self.active.clone(),
            wrapped_dek,
            ciphertext,
        })
    }

    /// Decrypts a sealed secret. An unknown `kek_id` names the id; any tag
    /// failure is a generic [`CryptoError::Decrypt`].
    pub fn open(&self, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let dek = self.unwrap_dek(sealed)?;
        decrypt(&dek, &sealed.ciphertext, aad)
    }

    /// Re-wraps the data key under the active KEK; `Ok(None)` when it already
    /// is. The ciphertext is untouched.
    pub fn rewrap(&self, sealed: &Sealed) -> Result<Option<Sealed>, CryptoError> {
        if sealed.kek_id == self.active {
            return Ok(None);
        }
        let dek = self.unwrap_dek(sealed)?;
        let wrapped_dek = encrypt(self.key(&self.active)?, &dek, &dek_aad(&self.active))?;
        Ok(Some(Sealed {
            kek_id: self.active.clone(),
            wrapped_dek,
            ciphertext: sealed.ciphertext.clone(),
        }))
    }

    fn key(&self, id: &str) -> Result<&[u8; KEY_LEN], CryptoError> {
        self.keys
            .get(id)
            .ok_or_else(|| CryptoError::UnknownKek(id.to_owned()))
    }

    fn unwrap_dek(&self, sealed: &Sealed) -> Result<Vec<u8>, CryptoError> {
        let kek = self.key(&sealed.kek_id)?;
        let dek = decrypt(kek, &sealed.wrapped_dek, &dek_aad(&sealed.kek_id))?;
        if dek.len() == KEY_LEN {
            Ok(dek)
        } else {
            Err(CryptoError::Decrypt)
        }
    }
}

fn valid_id(id: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn dek_aad(kek_id: &str) -> Vec<u8> {
    let mut aad = DEK_AAD_PREFIX.to_vec();
    aad.extend_from_slice(kek_id.as_bytes());
    aad
}

/// Output length marker for HKDF.
struct KeyLen;

impl KeyType for KeyLen {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

fn derive_kek(secret: &str) -> Result<[u8; KEY_LEN], CryptoError> {
    let prk = Salt::new(HKDF_SHA256, HKDF_SALT).extract(secret.as_bytes());
    let mut key = [0_u8; KEY_LEN];
    prk.expand(&[HKDF_INFO], KeyLen)
        .and_then(|okm| okm.fill(&mut key))
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(key)
}

/// `k` plus the first 8 hex characters of the SHA-256 of the derived key.
fn auto_id(key: &[u8; KEY_LEN]) -> String {
    let hash = digest(&SHA256, key);
    let hex = hex::encode(hash.as_ref());
    format!("k{}", hex.get(..8).unwrap_or(&hex))
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError::Encrypt)
}

/// `nonce(12) || ciphertext || tag(16)`.
fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = aead_key(key)?;
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| CryptoError::Random)?;
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(aad),
        &mut in_out,
    )
    .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

fn decrypt(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (nonce_bytes, body) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| CryptoError::Decrypt)?;
    let key = aead_key(key).map_err(|_| CryptoError::Decrypt)?;
    let mut in_out = body.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "oldoldoldoldoldoldoldoldoldoldoldoldoldoldold1";
    const NEW: &str = "newnewnewnewnewnewnewnewnewnewnewnewnewnewnew1";

    fn ring_of(text: &str) -> Keyring {
        Keyring::from_text(text).unwrap()
    }

    #[test]
    fn round_trip() {
        let ring = ring_of(&format!("a:{OLD}"));
        let sealed = ring.seal(b"hunter2", b"row-1").unwrap();
        assert_eq!(sealed.kek_id, "a");
        assert_eq!(ring.open(&sealed, b"row-1").unwrap(), b"hunter2");
    }

    #[test]
    fn nonces_are_fresh() {
        let ring = ring_of(OLD);
        let a = ring.seal(b"same", b"x").unwrap();
        let b = ring.seal(b"same", b"x").unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
    }

    #[test]
    fn wrong_aad_fails() {
        let ring = ring_of(OLD);
        let sealed = ring.seal(b"hunter2", b"row-1").unwrap();
        assert!(matches!(
            ring.open(&sealed, b"row-2"),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn tampering_fails() {
        let ring = ring_of(OLD);
        let sealed = ring.seal(b"hunter2", b"row-1").unwrap();

        let mut bad = sealed.clone();
        *bad.ciphertext.last_mut().unwrap() ^= 1;
        assert!(matches!(
            ring.open(&bad, b"row-1"),
            Err(CryptoError::Decrypt)
        ));

        let mut bad = sealed.clone();
        bad.wrapped_dek[0] ^= 1;
        assert!(matches!(
            ring.open(&bad, b"row-1"),
            Err(CryptoError::Decrypt)
        ));

        let mut bad = sealed;
        bad.ciphertext.truncate(5);
        assert!(matches!(
            ring.open(&bad, b"row-1"),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn rotation_by_rewrap() {
        let old_ring = ring_of(&format!("old:{OLD}"));
        let sealed = old_ring.seal(b"hunter2", b"row-1").unwrap();

        let rotated = ring_of(&format!("new:{NEW}\nold:{OLD}"));
        assert_eq!(rotated.active_id(), "new");
        assert_eq!(rotated.open(&sealed, b"row-1").unwrap(), b"hunter2");

        let moved = rotated.rewrap(&sealed).unwrap().unwrap();
        assert_eq!(moved.kek_id, "new");
        assert_eq!(moved.ciphertext, sealed.ciphertext);
        assert!(rotated.rewrap(&moved).unwrap().is_none());

        let new_only = ring_of(&format!("new:{NEW}"));
        assert_eq!(new_only.open(&moved, b"row-1").unwrap(), b"hunter2");
        match new_only.open(&sealed, b"row-1") {
            Err(CryptoError::UnknownKek(id)) => assert_eq!(id, "old"),
            other => panic!("expected UnknownKek, got {other:?}"),
        }
    }

    #[test]
    fn short_secret_refused() {
        assert!(matches!(
            Keyring::from_text("a:tooshort"),
            Err(CryptoError::ShortSecret { line: 1 })
        ));
        assert!(matches!(
            Keyring::from_text("tooshort"),
            Err(CryptoError::ShortSecret { line: 1 })
        ));
    }

    #[test]
    fn duplicate_id_refused() {
        let text = format!("a:{OLD}\na:{NEW}");
        assert!(matches!(
            Keyring::from_text(&text),
            Err(CryptoError::DuplicateId(id)) if id == "a"
        ));
    }

    #[test]
    fn bad_id_refused() {
        assert!(matches!(
            Keyring::from_text(&format!("bad id:{OLD}")),
            Err(CryptoError::BadId { line: 1 })
        ));
        assert!(matches!(
            Keyring::from_text(&format!(":{OLD}")),
            Err(CryptoError::BadId { line: 1 })
        ));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let text = format!("# the active key\n\n  a:{OLD}  \n# old\nb:{NEW}\n");
        let ring = ring_of(&text);
        assert_eq!(ring.active_id(), "a");
        assert!(ring.keys.contains_key("b"));
    }

    #[test]
    fn empty_text_refused() {
        assert!(matches!(
            Keyring::from_text("# nothing\n\n"),
            Err(CryptoError::NoKeys)
        ));
    }

    #[test]
    fn id_is_derived_without_one() {
        let ring = ring_of(OLD);
        let id = ring.active_id();
        assert_eq!(id.len(), 9);
        assert!(id.starts_with('k'));
        assert!(id[1..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, ring_of(OLD).active_id());
    }

    #[test]
    fn sources_none_when_unset_or_empty() {
        assert!(Keyring::from_sources(None, None).unwrap().is_none());
        assert!(
            Keyring::from_sources(Some(" "), Some("\n"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn inline_source_and_file_wins() {
        let ring = Keyring::from_sources(None, Some(&format!("a:{OLD}")))
            .unwrap()
            .unwrap();
        assert_eq!(ring.active_id(), "a");

        let missing = Keyring::from_sources(Some("/nonexistent/axon-kek"), Some(OLD));
        assert!(matches!(missing, Err(CryptoError::ReadFile { .. })));
    }

    #[test]
    fn debug_shows_ids_only() {
        let shown = format!("{:?}", ring_of(&format!("a:{OLD}")));
        assert!(shown.contains("\"a\""));
        assert!(!shown.contains(OLD));
    }
}
