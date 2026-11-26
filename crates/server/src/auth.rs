//! Bearer-token roles (viewer / operator). Tokens live in a file outside the config;
//! comparisons are constant-time. Header-based auth (no cookies) avoids CSRF.

use axum::http::HeaderMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Operator,
}

#[derive(Debug, Clone, Default)]
pub struct Tokens {
    operator: Vec<Vec<u8>>,
    viewer: Vec<Vec<u8>>,
    /// Loopback-only development mode without tokens (explicit and logged).
    pub dev_open: bool,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Tokens {
    /// Parse `operator=<token>` / `viewer=<token>` lines; tokens must be >= 24 chars.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut t = Tokens::default();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (role, tok) = line.split_once('=').ok_or(format!("line {}: expected role=token", i + 1))?;
            let tok = tok.trim();
            if tok.len() < 24 {
                return Err(format!("line {}: token too short (>= 24 chars required)", i + 1));
            }
            match role.trim() {
                "operator" => t.operator.push(tok.as_bytes().to_vec()),
                "viewer" => t.viewer.push(tok.as_bytes().to_vec()),
                r => return Err(format!("line {}: unknown role {r}", i + 1)),
            }
        }
        if t.operator.is_empty() {
            return Err("at least one operator token is required".into());
        }
        Ok(t)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        Self::parse(&std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?)
    }

    pub fn dev_open() -> Self {
        Tokens { dev_open: true, ..Default::default() }
    }

    /// Resolve the caller's role from `Authorization: Bearer ...`.
    pub fn role(&self, headers: &HeaderMap) -> Option<Role> {
        if self.dev_open {
            return Some(Role::Operator);
        }
        let v = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
        let tok = v.strip_prefix("Bearer ")?.trim().as_bytes();
        if self.operator.iter().any(|t| ct_eq(t, tok)) {
            return Some(Role::Operator);
        }
        if self.viewer.iter().any(|t| ct_eq(t, tok)) {
            return Some(Role::Viewer);
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        let t = Tokens::parse("operator=aaaaaaaaaaaaaaaaaaaaaaaaaaaa\nviewer=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n").unwrap();
        let mut h = HeaderMap::new();
        assert_eq!(t.role(&h), None);
        h.insert("authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap());
        assert_eq!(t.role(&h), Some(Role::Operator));
        h.insert("authorization", "Bearer bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".parse().unwrap());
        assert_eq!(t.role(&h), Some(Role::Viewer));
        h.insert("authorization", "Bearer wrong".parse().unwrap());
        assert_eq!(t.role(&h), None);
        assert!(Tokens::parse("operator=short").is_err());
        assert!(Tokens::parse("viewer=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").is_err());
    }
}
