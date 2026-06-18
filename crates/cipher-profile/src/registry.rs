//! Built-in and user-defined profile registry.

use crate::error::CipherProfileError;
use crate::layer::CipherLayer;
use crate::profile::{CipherProfile, CipherProfileBuilder};
use crate::shamir_cfg::ShamirConfig;
use ephemeral_session::SessionCurve;
use heapless::Vec;

const BUILTIN: &[&str] = &[
    "standard",
    "conservative",
    "conservative-shamir",
    "high-assurance",
];

/// Registry of up to 16 profiles (4 built-in + up to 12 user).
pub struct ProfileRegistry {
    profiles: Vec<CipherProfile, 16>,
}

impl ProfileRegistry {
    /// Registry containing built-in profiles only.
    pub fn with_builtins() -> Self {
        let mut profiles = Vec::new();
        for p in [
            builtin_standard(),
            builtin_conservative(),
            builtin_conservative_shamir(),
            builtin_high_assurance(),
        ] {
            match p {
                Ok(profile) => {
                    let _ = profiles.push(profile);
                }
                Err(e) => {
                    panic!("built-in profile invariant violated: {:?}", e);
                }
            }
        }
        Self { profiles }
    }

    /// Register a user profile (name must not collide with an existing entry).
    pub fn register(&mut self, profile: CipherProfile) -> Result<(), CipherProfileError> {
        if self.profiles.len() >= 16 {
            return Err(CipherProfileError::RegistryFull);
        }
        if self.get(profile.name()).is_some() {
            return Err(CipherProfileError::InvalidProfileName);
        }
        self.profiles
            .push(profile)
            .map_err(|_| CipherProfileError::RegistryFull)?;
        Ok(())
    }

    /// Look up by name.
    pub fn get(&self, name: &str) -> Option<&CipherProfile> {
        self.profiles.iter().find(|p| p.name() == name)
    }

    /// All profile names currently stored.
    pub fn list(&self) -> Vec<&str, 16> {
        let mut out = Vec::new();
        for p in self.profiles.iter() {
            let _ = out.push(p.name());
        }
        out
    }

    /// Remove a user-defined profile. Built-ins cannot be removed.
    pub fn remove(&mut self, name: &str) -> Result<(), CipherProfileError> {
        if BUILTIN.contains(&name) {
            return Err(CipherProfileError::ProfileLocked);
        }
        let mut i = 0usize;
        while i < self.profiles.len() {
            if self.profiles[i].name() == name {
                let _ = self.profiles.swap_remove(i);
                return Ok(());
            }
            i += 1;
        }
        Err(CipherProfileError::ProfileNotFound)
    }
}

fn builtin_standard() -> Result<CipherProfile, CipherProfileError> {
    CipherProfileBuilder::new("standard")?
        .description("Single ChaCha20-Poly1305; BP256r1 ECDHE")
        .curve(SessionCurve::BrainpoolP256r1)
        .layer(CipherLayer::ChaCha20Poly1305)?
        .shamir(ShamirConfig::none())
        .build()
}

fn builtin_conservative() -> Result<CipherProfile, CipherProfileError> {
    CipherProfileBuilder::new("conservative")?
        .description("ChaCha inner, Serpent outer (CESS suite_id 0x0003); BP256r1")
        .curve(SessionCurve::BrainpoolP256r1)
        .layer(CipherLayer::ChaCha20Poly1305)?
        .layer(CipherLayer::Serpent256)?
        .shamir(ShamirConfig::none())
        .build()
}

fn builtin_conservative_shamir() -> Result<CipherProfile, CipherProfileError> {
    CipherProfileBuilder::new("conservative-shamir")?
        .description("Same cascade as conservative; Shamir 3-of-5")
        .curve(SessionCurve::BrainpoolP256r1)
        .layer(CipherLayer::ChaCha20Poly1305)?
        .layer(CipherLayer::Serpent256)?
        .shamir(ShamirConfig::new(3, 5)?)
        .build()
}

fn builtin_high_assurance() -> Result<CipherProfile, CipherProfileError> {
    CipherProfileBuilder::new("high-assurance")?
        .description("ChaCha inner, Serpent outer (CESS suite_id 0x0012); BP512r1; Shamir 3-of-5")
        .curve(SessionCurve::BrainpoolP512r1)
        .layer(CipherLayer::ChaCha20Poly1305)?
        .layer(CipherLayer::Serpent256)?
        .shamir(ShamirConfig::new(3, 5)?)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tr<T, E: core::fmt::Debug>(r: Result<T, E>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn registry_builtins_present() {
        let r = ProfileRegistry::with_builtins();
        let names = r.list();
        for n in BUILTIN.iter() {
            assert!(names.iter().any(|x| *x == *n));
        }
    }

    #[test]
    fn registry_get_standard() {
        let r = ProfileRegistry::with_builtins();
        let Some(p) = r.get("standard") else {
            panic!("missing standard");
        };
        assert_eq!(p.layers(), &[CipherLayer::ChaCha20Poly1305]);
    }

    #[test]
    fn registry_get_conservative() {
        let r = ProfileRegistry::with_builtins();
        let Some(p) = r.get("conservative") else {
            panic!("missing conservative");
        };
        assert_eq!(
            p.layers(),
            &[CipherLayer::ChaCha20Poly1305, CipherLayer::Serpent256]
        );
    }

    #[test]
    fn registry_get_high_assurance() {
        let r = ProfileRegistry::with_builtins();
        let Some(p) = r.get("high-assurance") else {
            panic!("missing high-assurance");
        };
        assert_eq!(p.curve(), SessionCurve::BrainpoolP512r1);
        assert_eq!(
            p.layers(),
            &[CipherLayer::ChaCha20Poly1305, CipherLayer::Serpent256]
        );
    }

    #[test]
    fn registry_user_profile() {
        let mut r = ProfileRegistry::with_builtins();
        let b = tr(CipherProfileBuilder::new("user-one"));
        let b = tr(b.curve(SessionCurve::BrainpoolP256r1).layer(CipherLayer::Aes256Gcm));
        let u = tr(b.build());
        tr(r.register(u));
        assert!(r.get("user-one").is_some());
        assert!(r.list().iter().any(|n| *n == "user-one"));
    }

    #[test]
    fn registry_duplicate_name() {
        let mut r = ProfileRegistry::with_builtins();
        let b = tr(CipherProfileBuilder::new("standard"));
        let b = tr(b.curve(SessionCurve::BrainpoolP256r1).layer(CipherLayer::Aes256Gcm));
        let u = tr(b.build());
        let e = r.register(u);
        assert_eq!(e, Err(CipherProfileError::InvalidProfileName));
    }

    #[test]
    fn registry_remove_builtin() {
        let mut r = ProfileRegistry::with_builtins();
        let e = r.remove("standard");
        assert_eq!(e, Err(CipherProfileError::ProfileLocked));
    }

    #[test]
    fn registry_remove_user() {
        let mut r = ProfileRegistry::with_builtins();
        let b = tr(CipherProfileBuilder::new("tmp-user"));
        let b = tr(b.curve(SessionCurve::BrainpoolP256r1).layer(CipherLayer::Aes256Gcm));
        let u = tr(b.build());
        tr(r.register(u));
        tr(r.remove("tmp-user"));
        assert!(r.get("tmp-user").is_none());
    }

    #[test]
    fn registry_full() {
        let mut r = ProfileRegistry::with_builtins();
        const NAMES: [&str; 12] = [
            "u00", "u01", "u02", "u03", "u04", "u05", "u06", "u07", "u08", "u09", "u10", "u11",
        ];
        for name in NAMES {
            let b = tr(CipherProfileBuilder::new(name));
            let b = tr(b.curve(SessionCurve::BrainpoolP256r1).layer(CipherLayer::Aes256Gcm));
            let p = tr(b.build());
            tr(r.register(p));
        }
        let b = tr(CipherProfileBuilder::new("overflow"));
        let b = tr(b.curve(SessionCurve::BrainpoolP256r1).layer(CipherLayer::Aes256Gcm));
        let extra = tr(b.build());
        let e = r.register(extra);
        assert_eq!(e, Err(CipherProfileError::RegistryFull));
    }
}
