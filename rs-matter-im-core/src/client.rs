/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! The client side of a single Interaction Model transaction.
//!
//! The generated cluster clients (`<Cluster>Client`) are written against the
//! traits in this module rather than against a concrete exchange type, so that
//! they do not depend on the transport.

use core::future::Future;

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVBuilderParent, TLVElement};
use crate::utils::sync::MaybeSend;

use super::{
    AttrResp, IMStatusCode, InvReqBuilder, InvokeResp, ReadReqBuilder, ReportDataResp,
    SubscribeReqBuilder, WriteReqBuilder, WriteResp,
};

/// The client side of a single Interaction Model transaction with a peer: one
/// Read, Write, Invoke or Subscribe request, and the response to it.
///
/// Each method consumes `self`, as one exchange carries one transaction. A further
/// transaction needs a new exchange.
///
/// There are two flavours of methods:
/// - `*_with` takes a `build` closure that writes the request. The closure may be
///   called more than once, when the request has to be sent again, and must write
///   the same request every time. The first chunk of the response is returned.
/// - `*_sender` returns a sender for the caller to drive manually. The API of the
///   senders is on their concrete types, so these methods are for callers that know
///   the implementor of this trait.
///
/// The generated per-cluster `<Cluster>Client` traits build on this trait, and add
/// single-shot methods for the commands and the attributes of the cluster.
pub trait ImClient: Sized {
    /// The sender of a Read request, which is also the parent of its builder.
    type ReadSender: TLVBuilderParent;
    /// The sender of a Write request, which is also the parent of its builder.
    type WriteSender: TLVBuilderParent;
    /// The sender of an Invoke request, which is also the parent of its builder.
    type InvokeSender: TLVBuilderParent;
    /// The sender of a Subscribe request, which is also the parent of its builder.
    type SubscribeSender: TLVBuilderParent;
    /// A chunk of the response to a Read request.
    type ReadChunk: ImReadChunk;
    /// The response to a Write request.
    type WriteHandle: ImWriteHandle;
    /// A chunk of the response to an Invoke request.
    type InvokeChunk: ImInvokeChunk;
    /// A chunk of the priming reports of a subscription.
    type SubscribeChunk;

    /// Send a Read request and return the first chunk of the response.
    fn read_with<B>(
        self,
        build: B,
    ) -> impl Future<Output = Result<Self::ReadChunk, Error>> + MaybeSend
    where
        B: FnMut(ReadReqBuilder<Self::ReadSender>) -> Result<Self::ReadSender, Error> + MaybeSend;

    /// Return a sender for driving a Read request manually.
    fn read_sender(self) -> impl Future<Output = Result<Self::ReadSender, Error>> + MaybeSend;

    /// Send a Write request and return the response.
    ///
    /// If `timed_timeout_ms` is `Some`, the request is preceded by a Timed
    /// Request with that timeout.
    fn write_with<B>(
        self,
        timed_timeout_ms: Option<u16>,
        build: B,
    ) -> impl Future<Output = Result<Self::WriteHandle, Error>> + MaybeSend
    where
        B: FnMut(WriteReqBuilder<Self::WriteSender>) -> Result<Self::WriteSender, Error>
            + MaybeSend;

    /// Return a sender for driving a Write request manually.
    ///
    /// If `timed_timeout_ms` is `Some`, a Timed Request with that timeout is sent first.
    fn write_sender(
        self,
        timed_timeout_ms: Option<u16>,
    ) -> impl Future<Output = Result<Self::WriteSender, Error>> + MaybeSend;

    /// Send an Invoke request and return the first chunk of the response.
    ///
    /// If `timed_timeout_ms` is `Some`, the request is preceded by a Timed
    /// Request with that timeout.
    fn invoke_with<B>(
        self,
        timed_timeout_ms: Option<u16>,
        build: B,
    ) -> impl Future<Output = Result<Self::InvokeChunk, Error>> + MaybeSend
    where
        B: FnMut(InvReqBuilder<Self::InvokeSender>) -> Result<Self::InvokeSender, Error>
            + MaybeSend;

    /// Return a sender for driving an Invoke request manually.
    ///
    /// If `timed_timeout_ms` is `Some`, a Timed Request with that timeout is sent first.
    fn invoke_sender(
        self,
        timed_timeout_ms: Option<u16>,
    ) -> impl Future<Output = Result<Self::InvokeSender, Error>> + MaybeSend;

    /// Send a Subscribe request and return the first chunk of the priming reports.
    ///
    /// This covers the establishment of the subscription only. The reports after
    /// it arrive from the peer on new exchanges.
    fn subscribe_with<B>(
        self,
        build: B,
    ) -> impl Future<Output = Result<Self::SubscribeChunk, Error>> + MaybeSend
    where
        B: FnMut(
                SubscribeReqBuilder<Self::SubscribeSender>,
            ) -> Result<Self::SubscribeSender, Error>
            + MaybeSend;

    /// Return a sender for driving a Subscribe request manually.
    fn subscribe_sender(
        self,
    ) -> impl Future<Output = Result<Self::SubscribeSender, Error>> + MaybeSend;
}

/// A chunk of the response to a Read request.
pub trait ImReadChunk: Sized {
    /// The response carried by this chunk.
    fn response(&self) -> Result<ReportDataResp<'_>, Error>;

    /// Acknowledge this chunk and return the next one, or `None` if this was
    /// the last one.
    fn complete(self) -> impl Future<Output = Result<Option<Self>, Error>> + MaybeSend;
}

/// A chunk of the response to an Invoke request.
pub trait ImInvokeChunk: Sized {
    /// The response carried by this chunk, or `None` if the peer replied with
    /// a status only.
    fn response(&self) -> Result<Option<InvokeResp<'_>>, Error>;

    /// Acknowledge this chunk and return the next one, or `None` if this was
    /// the last one.
    fn complete(self) -> impl Future<Output = Result<Option<Self>, Error>> + MaybeSend;
}

/// The response to a Write request.
pub trait ImWriteHandle {
    /// The response.
    fn response(&self) -> Result<WriteResp<'_>, Error>;
}

/// Send a Read request for a single attribute and return its value.
///
/// If the peer replies with an error, or the value cannot be decoded, the error is
/// returned without consuming the rest of the response.
pub async fn read_attr<T, B, V>(tx: T, build: B) -> Result<V, Error>
where
    T: ImClient,
    B: FnMut(ReadReqBuilder<T::ReadSender>) -> Result<T::ReadSender, Error> + MaybeSend,
    V: for<'a> FromTLV<'a>,
{
    let mut chunk = tx.read_with(build).await?;

    let value = V::from_tlv(&attr_data(chunk.response()?)??)?;

    while let Some(next) = chunk.complete().await? {
        chunk = next;
    }

    Ok(value)
}

/// Send a Read request for a single attribute, and call `f` with the data of the attribute
/// while the response is still available.
///
/// `f` also gets the error if the peer replied with an error for the attribute.
pub async fn read_attr_with<T, B, F, R>(tx: T, build: B, f: F) -> Result<R, Error>
where
    T: ImClient,
    B: FnMut(ReadReqBuilder<T::ReadSender>) -> Result<T::ReadSender, Error> + MaybeSend,
    F: for<'a> FnOnce(Result<TLVElement<'a>, Error>) -> R,
{
    let mut chunk = tx.read_with(build).await?;

    let out = f(attr_data(chunk.response()?)?);

    while let Some(next) = chunk.complete().await? {
        chunk = next;
    }

    Ok(out)
}

/// Send a Write request and return an error if the peer failed any of the writes.
pub async fn write_attr<T, B>(tx: T, timed_timeout_ms: Option<u16>, build: B) -> Result<(), Error>
where
    T: ImClient,
    B: FnMut(WriteReqBuilder<T::WriteSender>) -> Result<T::WriteSender, Error> + MaybeSend,
{
    let handle = tx.write_with(timed_timeout_ms, build).await?;

    for status in handle.response()?.write_responses.iter() {
        let status = status?.status.status;

        if status != IMStatusCode::Success {
            return Err(status_error(status));
        }
    }

    Ok(())
}

/// Send an Invoke request for a command without a response, and consume the status reply.
pub async fn invoke_cmd<T, B>(tx: T, timed_timeout_ms: Option<u16>, build: B) -> Result<(), Error>
where
    T: ImClient,
    B: FnMut(InvReqBuilder<T::InvokeSender>) -> Result<T::InvokeSender, Error> + MaybeSend,
{
    complete_invoke(tx.invoke_with(timed_timeout_ms, build).await?).await
}

/// Acknowledge the provided chunk and all the chunks following it.
pub async fn complete_invoke<C: ImInvokeChunk>(mut chunk: C) -> Result<(), Error> {
    while let Some(next) = chunk.complete().await? {
        chunk = next;
    }

    Ok(())
}

/// Return the data of the single attribute in a response to a Read request.
///
/// The outer error is for a malformed response, the inner one is for the peer
/// replying with an error for the attribute.
fn attr_data(resp: ReportDataResp<'_>) -> Result<Result<TLVElement<'_>, Error>, Error> {
    let attr_reports = resp.attr_reports.as_ref().ok_or(ErrorCode::InvalidData)?;

    let attr_resp = attr_reports
        .iter()
        .next()
        .ok_or(ErrorCode::InvalidData)?
        .map_err(|_| ErrorCode::InvalidData)?;

    Ok(match attr_resp {
        AttrResp::Data(data) => Ok(data.data),
        AttrResp::Status(status) => Err(status_error(status.status.status)),
    })
}

fn status_error(status: IMStatusCode) -> Error {
    status.to_error_code().unwrap_or(ErrorCode::Failure).into()
}
