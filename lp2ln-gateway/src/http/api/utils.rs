use bytes::Bytes;
use http_body_util::{combinators::BoxBody, Full};
use std::convert::Infallible;
use http_body_util::BodyExt;

pub fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).map_err(|_| unreachable!()).boxed()
} 