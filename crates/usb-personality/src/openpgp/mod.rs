//! OpenPGP card application (v3.4) over ISO 7816-4 APDUs.

#![deny(unsafe_code)]

pub mod aid;
pub mod apdu;
pub mod backend;
pub mod dispatch;
pub mod do_store;
pub mod dos;
pub mod error;
pub mod state;
pub mod vault_backend;

pub mod commands;

pub use aid::{aid_matches_openpgp, build_aid, OPENPGP_AID_PREFIX};
pub use apdu::{ApduError, CommandApdu, ResponseApdu};
pub use backend::{OpenPgpAudit, OpenPgpBackend, OpenPgpBackendError, OpenPgpKeySlot, NullAudit};
pub use vault_backend::{NoopZeroise, OpenPgpVaultBackend};
pub use dispatch::{handle_apdu, OpenPgpCcidDispatcher, OpenPgpDispatch};
pub use do_store::{DoStore, DoStoreError, DO_STORE_MAGIC, DO_STORE_REGION_BYTES};
pub use dos::{compute_v4_fingerprint, pin_bytes_to_verifier_digest, AlgorithmAttributes};
pub use error::StatusWord;
pub use state::CardState;

/// Reset OpenPGP session state and notify backend when the token is locked (PIN exhaustion or explicit lock).
///
/// **Security role:** clears PIN verification flags; integrator should trigger USB re-enumeration so the
/// host drops cached OpenPGP state.
pub fn on_token_lock<B: OpenPgpBackend>(state: &mut CardState, backend: &mut B) {
    state.reset();
    backend.on_lock_disconnect();
    backend.log_event(0xFFFF_0001);
}
