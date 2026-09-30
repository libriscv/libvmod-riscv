//! The single VCL variable access table.
//!
//! Variable families with a `*` suffix match arbitrary HTTP header names.
//! Type checking and lowering both consume this table; no phase permission is
//! duplicated in either stage.

use crate::types::{Phase, ValueType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lowering {
    RequestHeader,
    ResponseHeader,
    RequestUrl,
    RequestMethod,
    ResponseStatus,
    Now,
    ClientIp,
    Ttl,
    StaleWhileRevalidate,
    StaleIfError,
    Uncacheable,
    CacheHit,
}

/// Identity-specific restrictions on writes to a variable family.
///
/// Phase permissions and value types are not enough for HTTP framing, the
/// routing-owned Host header, or the one-way uncacheable flag. Keeping those
/// facts in the variable row prevents the checker from growing a parallel
/// list keyed by variable spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteConstraint {
    None,
    Header,
    RecvRequestHeader,
    TrueOnly,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VariableSpec {
    pub pattern: &'static str,
    pub value_type: ValueType,
    pub readable: &'static [Phase],
    pub writable: &'static [Phase],
    pub lowering: Lowering,
    pub write_constraint: WriteConstraint,
}

include!("vcl_vars.def");

pub(crate) fn is_framing_header(name: &str) -> bool {
    FRAMING_HEADERS
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

pub(crate) fn resolve(name: &str) -> Option<(&'static VariableSpec, Option<&str>)> {
    VARIABLES.iter().find_map(|spec| {
        if let Some(prefix) = spec.pattern.strip_suffix('*') {
            name.strip_prefix(prefix)
                .filter(|suffix| !suffix.is_empty())
                .map(|suffix| (spec, Some(suffix)))
        } else if name == spec.pattern {
            Some((spec, None))
        } else {
            None
        }
    })
}
