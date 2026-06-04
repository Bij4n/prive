//! The unlock-once agent: a small background process that keeps an opened database in memory
//! for a while, so a working session costs one password prompt.
//!
//! Unix only for now (a Unix-domain socket in a private directory). On other systems every
//! command asks for the password, as before.

#[cfg(unix)]
pub mod dir;
pub mod proto;
