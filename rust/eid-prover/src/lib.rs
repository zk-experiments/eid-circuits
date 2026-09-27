//! Prover side of eid-circuits: reads an eMRTD's NFC data (EF.SOD, DG1),
//! selects the step circuits it needs, and checks the document natively
//! before any proving.

pub mod config;
pub mod mrz;
pub mod select;
pub mod sod;
pub mod witness;

pub use select::{select, Selection};
pub use witness::{witnesses, Params, Witnesses};
