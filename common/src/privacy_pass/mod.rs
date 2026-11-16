//! RFC 9577/9578 type 0x0002 wire formats. Parsing does not verify signatures
//! or validate an advertised SPKI's algorithm; those are the crypto consumer's job.
use base64ct::{Base64Url, Encoding};
use sha2::{Digest, Sha256};

pub const TOKEN_TYPE: u16 = 0x0002;
pub const TOKEN_REQUEST_LEN: usize = 259;
pub const TOKEN_RESPONSE_LEN: usize = 256;
pub const TOKEN_LEN: usize = 354;
pub const TOKEN_INPUT_LEN: usize = 98;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid Privacy Pass encoding")
    }
}
impl std::error::Error for Error {}

/// Hash the exact advertised RFC 9578 RSA-PSS SPKI (never re-encode it).
pub fn token_key_id(advertised_spki: &[u8]) -> [u8; 32] {
    Sha256::digest(advertised_spki).into()
}
pub fn truncated_token_key_id(key_id: &[u8; 32]) -> u8 {
    key_id[31]
}
pub fn token_input(
    nonce: &[u8; 32],
    challenge_digest: &[u8; 32],
    key_id: &[u8; 32],
) -> [u8; TOKEN_INPUT_LEN] {
    let mut out = [0; TOKEN_INPUT_LEN];
    out[..2].copy_from_slice(&TOKEN_TYPE.to_be_bytes());
    out[2..34].copy_from_slice(nonce);
    out[34..66].copy_from_slice(challenge_digest);
    out[66..98].copy_from_slice(key_id);
    out
}
fn typed(bytes: &[u8], length: usize) -> Result<(), Error> {
    if bytes.len() != length || bytes[..2] != TOKEN_TYPE.to_be_bytes() {
        return Err(Error);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRequest {
    pub truncated_token_key_id: u8,
    pub blinded_msg: [u8; 256],
}
impl TokenRequest {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        typed(bytes, TOKEN_REQUEST_LEN)?;
        Ok(Self {
            truncated_token_key_id: bytes[2],
            blinded_msg: bytes[3..].try_into().map_err(|_| Error)?,
        })
    }
    pub fn to_bytes(&self) -> [u8; TOKEN_REQUEST_LEN] {
        let mut out = [0; TOKEN_REQUEST_LEN];
        out[..2].copy_from_slice(&TOKEN_TYPE.to_be_bytes());
        out[2] = self.truncated_token_key_id;
        out[3..].copy_from_slice(&self.blinded_msg);
        out
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenResponse {
    pub blind_sig: [u8; 256],
}
impl TokenResponse {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            blind_sig: bytes.try_into().map_err(|_| Error)?,
        })
    }
    pub fn to_bytes(&self) -> [u8; TOKEN_RESPONSE_LEN] {
        self.blind_sig
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub nonce: [u8; 32],
    pub challenge_digest: [u8; 32],
    pub token_key_id: [u8; 32],
    pub authenticator: [u8; 256],
}
impl Token {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        typed(bytes, TOKEN_LEN)?;
        Ok(Self {
            nonce: bytes[2..34].try_into().map_err(|_| Error)?,
            challenge_digest: bytes[34..66].try_into().map_err(|_| Error)?,
            token_key_id: bytes[66..98].try_into().map_err(|_| Error)?,
            authenticator: bytes[98..].try_into().map_err(|_| Error)?,
        })
    }
    pub fn token_input(&self) -> [u8; TOKEN_INPUT_LEN] {
        token_input(&self.nonce, &self.challenge_digest, &self.token_key_id)
    }
    pub fn to_bytes(&self) -> [u8; TOKEN_LEN] {
        let mut out = [0; TOKEN_LEN];
        out[..98].copy_from_slice(&self.token_input());
        out[98..].copy_from_slice(&self.authenticator);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenChallenge {
    issuer_name: String,
    redemption_context: Vec<u8>,
    origin_info: String,
}
// RFC server names exclude userinfo, whitespace and non-ASCII. Restrict to
// URI authority host/port characters, including bracketed IP literals.
fn server_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))
}
impl TokenChallenge {
    /// Application policy constructor: exactly one Origin name.
    pub fn new(
        issuer_name: &str,
        redemption_context: &[u8],
        origin_name: &str,
    ) -> Result<Self, Error> {
        if !server_name(origin_name) {
            return Err(Error);
        }
        Self::from_parts(issuer_name, redemption_context, origin_name)
    }
    fn from_parts(issuer: &str, context: &[u8], origins: &str) -> Result<Self, Error> {
        if !server_name(issuer)
            || issuer.len() > u16::MAX as usize
            || !matches!(context.len(), 0 | 32)
            || origins.len() > u16::MAX as usize
            || (!origins.is_empty() && !origins.split(',').all(server_name))
        {
            return Err(Error);
        }
        Ok(Self {
            issuer_name: issuer.into(),
            redemption_context: context.into(),
            origin_info: origins.into(),
        })
    }
    pub fn issuer_name(&self) -> &str {
        &self.issuer_name
    }
    pub fn redemption_context(&self) -> &[u8] {
        &self.redemption_context
    }
    pub fn origin_info(&self) -> &str {
        &self.origin_info
    }
    /// Core RFC parser permits empty and comma-separated Origin names.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader(bytes);
        if r.u16()? != TOKEN_TYPE {
            return Err(Error);
        }
        let n = r.u16()? as usize;
        let issuer = std::str::from_utf8(r.take(n)?).map_err(|_| Error)?;
        let n = r.take(1)?[0] as usize;
        let context = r.take(n)?;
        let n = r.u16()? as usize;
        let origins = std::str::from_utf8(r.take(n)?).map_err(|_| Error)?;
        if !r.0.is_empty() {
            return Err(Error);
        }
        Self::from_parts(issuer, context, origins)
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = TOKEN_TYPE.to_be_bytes().to_vec();
        out.extend_from_slice(&(self.issuer_name.len() as u16).to_be_bytes());
        out.extend_from_slice(self.issuer_name.as_bytes());
        out.push(self.redemption_context.len() as u8);
        out.extend_from_slice(&self.redemption_context);
        out.extend_from_slice(&(self.origin_info.len() as u16).to_be_bytes());
        out.extend_from_slice(self.origin_info.as_bytes());
        out
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.serialize()).into()
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error)?,
        ))
    }
}

pub fn build_authorization_header(token: &Token) -> String {
    format!(
        "PrivateToken token=\"{}\"",
        Base64Url::encode_string(&token.to_bytes())
    )
}
pub fn build_challenge_header(
    challenge: &TokenChallenge,
    advertised_spki: &[u8],
    max_age: u64,
) -> String {
    format!(
        "PrivateToken challenge=\"{}\", token-key=\"{}\", max-age={}",
        Base64Url::encode_string(&challenge.serialize()),
        Base64Url::encode_string(advertised_spki),
        max_age
    )
}
fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
/// Parse one credentials field, ignoring syntactically valid unknown parameters.
/// Canonical padded base64url is required (padding is absent when unnecessary).
pub fn parse_authorization_header(header: &str) -> Result<Token, Error> {
    if !header.is_ascii() || header.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
        return Err(Error);
    }
    let split = header.find([' ', '\t']).ok_or(Error)?;
    if !header[..split].eq_ignore_ascii_case("PrivateToken") {
        return Err(Error);
    }
    let mut rest = header[split..].trim_matches([' ', '\t']);
    let mut token = None;
    loop {
        let n = rest.bytes().take_while(|b| tchar(*b)).count();
        if n == 0 {
            return Err(Error);
        }
        let name = &rest[..n];
        rest = rest[n..].trim_start_matches([' ', '\t']);
        rest = rest
            .strip_prefix('=')
            .ok_or(Error)?
            .trim_start_matches([' ', '\t']);
        let mut value = String::new();
        if let Some(quoted) = rest.strip_prefix('"') {
            let mut chars = quoted.char_indices();
            let end = loop {
                match chars.next() {
                    Some((i, '"')) => break i + 1,
                    Some((_, '\\')) => value.push(chars.next().ok_or(Error)?.1),
                    Some((_, c)) => value.push(c),
                    None => return Err(Error),
                }
            };
            rest = &quoted[end..];
        } else {
            let n = rest.bytes().take_while(|b| tchar(*b)).count();
            if n == 0 {
                return Err(Error);
            }
            value.push_str(&rest[..n]);
            rest = &rest[n..];
        }
        if name.eq_ignore_ascii_case("token") {
            if token.is_some() {
                return Err(Error);
            }
            let bytes = Base64Url::decode_vec(&value).map_err(|_| Error)?;
            if Base64Url::encode_string(&bytes) != value {
                return Err(Error);
            }
            token = Some(Token::from_bytes(&bytes)?);
        }
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            return token.ok_or(Error);
        }
        rest = rest
            .strip_prefix(',')
            .ok_or(Error)?
            .trim_start_matches([' ', '\t']);
    }
}

#[cfg(test)]
mod tests;
