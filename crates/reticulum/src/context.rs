// TODO: Find better name, 'context' is lazy.

use crate::destination::{Destination, Out, Plain, RNS_PATH_REQUEST_DESTINATION};

pub trait Context {
    /// Specifies which destinations are accepting path requests. Only packets
    /// received to these destinations will be considered.
    fn path_request_destinations() -> &'static [Destination<'static, Plain, Out, ()>];
}

/// Context as it is used in RNS.
#[derive(Debug)]
pub struct RnsContext;

impl Context for RnsContext {
    fn path_request_destinations() -> &'static [Destination<'static, Plain, Out, ()>] {
        &[RNS_PATH_REQUEST_DESTINATION]
    }
}
