# RFC - Transport / Exchange Layer Improvements

## Terminology

Throughout this document, the code in `rs-matter` which is responsible for dealing with the network (sending and receiving packets, including their decoding and encoding) is called the _transport layer_. It is also sometimes interchangeably named the _exchange layer_. The _exchange layer_ name is emphasizing the API aspects of the functionality, whereas it is providing the "exchange" API to user code / upper layers.

When comparing with the "Layered Architecture" diagram in the Matter spec, by "transport / exchange layer" we mean all of:
* (Probably) Action Framing
* Security
* Message Framing + Routing
* IP Framing + Transport Management

By _user code_ / _upper layer(s)_ (which mean the same thing actually throughout the document), we mean any code within or outside the `rs-matter` codebase that is using exclusively or mostly the _public_ "exchange" API of the such-defined transport layer.

When comparing with the "Layered Architecture" diagram in the Matter spec, by "user code / upper layers" we mean all of:
* Interaction Model
* Data Model
* Application Layer

## Intro

Back in 2023Q2, the new exchange concept - represented by the [`Exchange` struct](https://github.com/project-chip/rs-matter/blob/main/rs-matter/src/transport/exchange.rs#L248) was introduced to `rs-matter`.

Unlike the C++ Matter SDK and the previous `rs-matter` transport code, the `Exchange` struct API allows for a straightforward, sequential looking sequence of sending and receiving messages with the other peer. No callbacks complexity, no explicit and error-prone state machines' management. I.e.

```rust
async fn handle_an_im_request(exchange: &mut Exchange<'_>, tx_buf: &mut Packet<'_>, rx_buf: &mut Packet<'_>) -> Result<(), Error> {
    // Get the first received packet via the exchange
    exchange.recv(rx_buf).await?;

    // Do something with the RX packet
    // ...

    // Write something in the TX packet
    tx_buf.reset();
    let tlv = TLVWriter::new(tx.write_buf()?)?;
    // ...

    // Send the TX packet and wait for the reply
    exchange.exchange(tx_buf, rx_buf).await?;

    // Do something with the reply which is in the RX packet
    // ...

    // ... and so on

    // That's all folks, w.r.t. this exchange!
    Ok(())
}
```

In the absence of blocking IO and multithreading, the above is really only possible by utilizing the Rust `async` syntax of course. Which is - after all - nothing else but a way to use "linear", sequential syntax, yet still get a bunch of (single-threaded, yet concurrent-IO friendly) state machines.

## Status Quo

While the worrying memory consumption of the auto-generated Rust state machines is still around ([here](https://github.com/rust-lang/rust/issues/62958), [here](https://github.com/rust-lang/rust/issues/108906), [here](https://github.com/rust-lang/rust/issues/59087) and a [potential first fix](https://github.com/rust-lang/rust/pull/120168), in the meantime we know how to control it at least to some extent (use references to pre-allocated large objects within the async code and don't allocate the large objects from _within_ the async code).

With the long-awaited `async-fn-in-trait` feature now part of Rust stable, with `gen async` on the horizon, as well as some other async features, we are betting on the right horse w.r.t. `async`.

Nevertheless, the initial `Exchange` implementation left a lot to be desired. Yet, we believe the main metaphor is solid, so the suggested / implemented changes do **not** change the metaphor, but rather enhance it and try to address all "duck taped places" / outstanding issues summarized below.

## Issue 1: Unsafe implementation that can actually cause Undefined Behavior (i.e. crash)

**TL;DR**: The current Exchange implementation is unsound, because it tries to implement a "completion" API in Rust. Basically, we have implemented [the Linux io-uring metaphor in Rust](https://www.cloudwego.io/blog/2023/04/17/introducing-monoio-a-high-performance-rust-runtime-based-on-io-uring/#pure-async-io-interface-based-on-gat) (or ["the DMA with non-owning buffers"](https://hackmd.io/@rust-ctcft/ryivZ5c85?print-pdf#/) - see p17 at the end), which is _impossible_ to do safely _with borrowed buffers_ (as we currently do!) with the existing Rust type system.

Fortunately, there is a relatively straightforward fix, which requires the internal Matter transport implementation to _own_ the RX/TX buffers rather than what is happening now - user code or the `Exchange` objects own the buffers and "lend" / borrow their `&mut` refs (actually worse - `*mut` refs) to the internal Matter implementation.

The [details](#appendix-a-undefined-behavior-in-current-exchange-impl) of the problem are at the end of the document.

### Solution

The solution is also how the "DMA" and "io-uring" problems are solved in general - by [the transport singleton **owning** the buffers and the `async` notification mechanism](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/transport/core.rs#L77), rather than the other way around which is the status quo:
* The transport singleton **owns** the RX/TX buffers as well as the `async` notification mechanism
* All `Exchange` objects keep a reference `&Matter` to the Matter stack and thus to the transport impl too. So they cannot "outlive" the transport singleton
* The RX/TX buffers and the notification are protected with an `async` Mutex-like synchronization primitive, so that at any point in time, either the transport singleton reads/writes from/to its own RX/TX buffers, or the user code, via one of the exchanges
* User code - via the `Exchange` structs - awaits for the RX/TX buffers to become available, and then receives an `async` Muterx Guard to these. More details below, in [Issue2](#issue-2-too-many-rxtx-buffers)

All of the above is implemented with a safe-only code.

## Issue 2: Too many RX/TX buffers

The current implementation of `Exchange::send`, `Exchange::recv` and `Exchange::exchange` all take user-supplied buffers. This means that in the general case, N active exchanges require N, or even N*2 buffers (one RX and one TX, because of `Exchange::exchange(&mut tx, &mut rx)` which needs both).

With 8 active exchanges this means 8 * (1583 + 1280) = ~23K memory just for the buffers. 

Granted, user (i.e. upper layer)-supplied buffers might be necessary in some cases _anyway_. Imagine answering long reads in the Interaction Model where the device is `await`-ing when e.g. reading data from the device HAL. For that case you **do** need to copy the RX data into a user supplied buffer, so that while you are populating the various attribute values in the TX data and potentially `await`-ing the HAL layer in-between, the transport can continue to operate and dispatch RX packets for _other_ exchanges. 

The problem however is that extra RX/TX buffers are _not_ always necessary, yet with the current API we are _always_ paying the price. 

Another problem is that these buffers currently _always_ have the shape of an `[u8]` slice, while the upper layer might ultimately need a different buffer.

For example, the Secure Channel implementation never awaits the device HAL, as it does not communicate with the device HAL in the first place. It is a pure computational code. What that means, is that - theoretically - it can read _directly_ from the RX buffer of the transport impl and write _directly_ to the TX buffer of the transport impl. Even if that means that while it does so, no new incoming UDP packets will be accepted by the transport layer and all other exchanges willing to send stuff would be `async`-waiting for the (single) TX buffer to become available. This is tolerable in that case because - again - the Secure Channel is a pure computational layer without doing any IO. So at least in theory, it should complete fast (putting aside delays due to complex elliptic curve calcs).

In practice, the Secure Channel does currently need interim buffers too, as in [here](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/secure_channel/case.rs#L74), [here](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/secure_channel/case.rs#L544), [here](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/secure_channel/core.rs#L56) and [here](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/secure_channel/core.rs#L60). (Which by the way need to be optimized.) But these are **on top** of the additional `[u8]` RX/TX buffers that the `Exchange` API currently requires. And they have a different shape. So it becomes a bit of a "too many buffers" situation.

Where we're getting with all of that is that the Exchange layer should not assume how the Secure Channel or Interaction Model layers operate. They might or might not need extra buffers. However, requiring them to always use extra `[u8]`-shaped buffers means we are trading off extra memory of a fixed shape for responsiveness _even when we don't necessarily have a responsiveness problem in the first place_ or we don't know what type of memory layout the upper layer actually needs for buffers.

Some extra info in [Appendix B](#appendix-b-digression-do-we-need-the-data-model-handlers-to-be-async-in-the-first-place).

### Solution

The improved transport/exchange layer operates off from a **single** pair of RX/TX buffers.

Its philosophy is that it is up to the upper layers (Interaction Model and Secure Channel) not to hold on to its single pair of RX/TX buffers for too long. Since the knowledge whether the upper layers would be holding on for too long on its RX/TX buffers is with these upper layers, it is _up to them to decide_ when or if to use additional buffers in the first place. It is also up to them to decide what the _shape_ and _lifetime_ of these additional buffers would be.

The exchange layer deciding on behalf of the upper layers is basically the current status quo, where the exchange layer is always immediately copying data from/to buffers supplied by the upper layers. Fine, but that means over-provisioning of memory which we are trying to solve in the first place.

#### Receiving Details

* The transport layer is concurrently and asynchronously trying to get a `&mut` ref to its own RX buffer, but only when the RX buffer is _already emptied or empty_. If the RX buffer is full with a previous packet for _some_ exchange, the transport layer waits until the corresponding `Exchange` instance consumes the content of the RX buffer and signals back that the RX buffer is empty again.
* At the same time, all active `Exchange` instances which are `await`-ing inside their `Exchange::recv` method, are concurrently and asynchronously trying to lock the `async` mutex protecting the RX buffer singleton. An `Exchange` instance will succeed doing so _only when the RX buffer is full_. Moreover, only when the RX buffer is full with data designated for _that concrete concrete Exchange_ which is trying to get hold of the RX buffer.
* `Exchange::recv().await` returns an `async` Mutex Guard in disguise. The user (e.g. the upper layer) can read freely the data in the buffer protected by this guard, including `await`-ing the HAL while operating on that data. However, the transport layer will _not_ be receiving other packets at that time (as there is a single RX buffer), potentially causing UDP packets from other peers to be dropped and re-transmitted if the OS packet queue is full. So the buffer returned from `Exchange::recv` should not be held for too long and if so (i.e. the "network bridge" case), the upper IM/Secure Channel layer shold pull the data in an interim buffer and drop the `async` Mutex guard it got via `Exchange::recv` thus singnalling the RX packet singleton as empty.

#### Sending Details
* The transport layer is concurrently and asynchronously trying to get a `&mut` ref to its own TX buffer, _but only when the TX buffer is full_. If the TX buffer is not full, this means no exchange has prepared data for sending. When the transport layer gets access to the (already full) TX buffer, it copies the data in there over UDP (or other protocols in future), then marks the buffer as empty and signals/wakes all exchanges potentially `await`-ing on the TX buffer, that it is releasing the `async` lock on it.
* At the same time, all active `Exchange` instances which are inside their `Exchange::init_send` methods, are concurrently and asynchronously trying to lock the `async` mutex protecting the TX buffer singleton. An `Exchange` instance will succeed doing so _only when the TX buffer is empty_, and only one exchange instance would succeed doing so, and the others would continue to wait.
* `Exchange::init_send().await` returns an `async` Mutex Guard in disguise as well. The user can write freely into the buffer protected by this guard, including `await`-ing the HAL while operating on that data. However, if it is slow in doing that, it would delay all other exchanges willing to send at that time. Since the transport layer is automatically sending ACKs for re-transmitted packets this is not the end of the world, but if an exchange is delayed too much, it might cause this or other peers to eventually time out the whole exchange. Therefore, the buffer returned from `Exchange::init_send` should not be held for too long and if so (i.e. the "network bridge" case), the upper IM/Secure Channel layer shold first prepare the data to be sent in its own buffer, and only then try to lock the common TX buffer when the data is ready to be sent.

#### Deadlock Avoidance

Given that the transport layer is offering the upper layers two separate async mutexes in disguise - one for the RX buffer, and another - for the TX buffer, how are we avoiding a deadlock situation. E.g.:
* Exchange 1 has successfully locked the RX buffer by calling `exchange.recv().await` and now tries to lock the TX buffer by awaiting `exchange.init_send().await` to complete
* Exchange 2 did the opposite: it had locked the TX buffer by completing `exchange.init_send().await` and is now awaiting for the RX buffer with `exchange.recv().await`?

The answer is that the new API currently simply does not allow this:
* Method `Exchange::recv` takes a `&mut self` of the `Exchange` struct, and - most importantly - the returned Guard wrapper looks as if it keeps a `&mut` ref to the `Exchange` object while the guard wrapper is still alive. 
* Metod `Exchange::init_send` does exactly the same.
* Similarly for the variations of the above methods - namely - `Exchange::recv_fetch`, `Exchange::sender`, `Exchange::send_with` and so on

What the above means is that the upper layer can either operate on the RX buffer, or on the TX buffer, but not simultaneously on both. In a way that also means that we are _forcing_ the upper layers to actually use interim buffers, as they can't really "write into the TX buffer while reading from the RX buffer". Even if we relaxed our deadlock-avoiding locking scheme so as the upper layers to additionally be allowed to lock the RX buffer first, and then - as a second and only as a second step - the TX buffer as well - that would be problematic when addressing "Issue 3" (packet re-transmission). More on that below.

So even though it seems we are "back to square one" and in a way forcing the upper layers to re-introduce additional buffers, this is not exactly the same as the current status quo, as we are no longer dictating the _shape_ or the _lifetime duration_ of these interim buffers. For example:
* Pase needs `Spake2p` instance, but this "buffer" is (a) valid throughout the whole Pase exchange (b) needs the data to be massaged first before pushing it into it
* Ditto for Case with its `CaseSession`
* Ditto for Case that does need extra buffers to first encrypt and/or sign content before pushing into TX
* The IM layer almost always needs a TX `&mut [u8]`-shaped buffer where it can stream the data to be returned in the response, but it might not necessarily need an RX buffer for the incoming request, as long as the clusters it needs to query / write to / invoke are not `await`-ing
* Some of the operations in the IM layer do not need any buffers at all - for example, processing a timeout request/response. Or processing a status respone to a chunked `ReportData` response. Or answering with a `Busy` / `Resource Exhausted` status code in case the IM layer cannot handle the incoming request
* etc.

#### I hear the arguments, but if we have to, can we revert to the old scheme, just in case?

If we decide so, that's easy:
* Make public only `Exchange::recv_into`, `Exchange::send` and `Exchange::send_from`
* Make `Exchange::recv_fetch`, `Exchange::rx`, `Exchange::recv`, `Sender` and `Exchange::init_send` private

That way upper layers would be _required_ to provide raw, `[u8]`-shaped buffers and the data will be read from/written to those immediately.
Yet, all other issues except the memory one would still be solved. And - a solution for Issues 1 and 6 in particular might anyway require a scheme similar to the proposed one.

## Issue 3: No packet re-transmission

The current transport layer does not have packet re-transmission implemented.

### Solution

The improved transport layer has packet re-transmission implemented.

The question here rather is - how is it possible to implement packet re-transmissions for _multiple_ exchanges by using a _single_ pair of RX/TX buffers in the first place? 

We are simply trading less memory usage for extra computation and some extra burden on the user / upper layers. To put it simply, the upper layers are _required_ to be capable of re-generating the TX payload of their packet (and then the exchange layer would re-encode it and re-send it again), until the exchange layer tells them it is no longer necessary (i.e. when an ACK is received).

While this sounds like a lot of lift and shift, the new public `Exchange` API provides plenty of utilities to get the job done:
* `Exchange::send_with(f: FnMut(&Exchange, &mut WriteBuf) -> Option<MessageMeta>)`
  * The transport layer will call the provided closure as many times as necessary (or just once for non-reliable packets); upper layer is only required to behave idempotently and generate the _same_ content and message meta-data every time
* `let sender = Sender::new(&mut exchange)` and then `while let Some(tx) = sender.tx() { let payload = tx.payload(); let mut wb = WriteBuf::new(payload); ... }`
  * Same as above, but also allows the upper layer to await while generating the content, as a non-async `FnMut` closure is not necessary (and Rust still lacks `AsyncFnMut`-style closures)
* `Exchange::send(payload: &[u8], meta: MessageMeta)`
  * The "old style" API where the message payload is prepared in a separate buffer, and then handed to the exchange layer for sending (and re-sending)

Here are a few examples from the actual `DataModel` IM layer, as to how packet retransmission looks like from the POV of layers above the transport one:

#### Example 1: Handling an IM "Timed" request

A "Timed" request might precede a "Write" or "Invoke" request. It only contains a "timeout" scalar `u32` value. As such, its processing and the (re)transmission of a response which is just a status response can be done without any intermediate buffers.


Here's how the "Timed" request-response interaction is coded:
```rust=
async fn timed(&self, exchange: &mut Exchange<'_>) -> Result<Duration, Error> {
    // Get access to the transport layer RX packet and convert it to a TimedReq struct
    let req = TimedReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
    debug!("IM: Timed request: {:?}", req);

    // Extract the timeout value. In a way, we _do_ use a buffer between the
    // above RX operation and the below TX operation. The buffer is `timeout_instant`.
    let timeout_instant = req.timeout_instant(exchange.matter().epoch);

    // Send (with re-transmission) a status response
    Self::send_status(exchange, IMStatusCode::Success).await?;

    Ok(timeout_instant)
}
```

As for `send_status`:
```rust=
async fn send_status(exchange: &mut Exchange<'_>, status: IMStatusCode) -> Result<(), Error> {
    exchange
        .send_with(|_, wb| {
            StatusResp::write(wb, status)?;

            Ok(Some(OpCode::StatusResponse.into()))
        })
        .await
}
```

Do note how `exchange.send_with` takes a (`FnMut`) closure. What this means is that once we call `send_with` and thus call the transport layer, we should be prepared our closure to be called multiple times, due to packet retransmissions, and until the transport layer receives an ACK for the packet we are transmitting. So our closure should be idempotent and generate the same payload every time it is called. Since the response is a simple status message, this is not a problem in this case.

#### Example 2: Answering an IM `Invoke` request:

Here's how the "Invoke" request-response interaction is coded:
```rust=
async fn invoke(
        &self,
        exchange: &mut Exchange<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<(), Error> {
    let req = InvReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;
    debug!("IM: Invoke request: {:?}", req);

    // (Handling timeouts is skipped for brevity)

    // To easily handle idempotent re-transmissions, we
    // simply allocate a TX buffer here and prepare the response inside it
    let Some(mut tx) = self.tx_buffer(exchange).await? else {
        return Ok(());
    };

    let mut wb = WriteBuf::new(&mut tx);

    let metadata = self.handler.lock().await;

    // Get the request shape by parsing the RX payload as TLV
    let req = InvReq::from_tlv(&get_root_node_struct(exchange.rx()?.payload())?)?;

    // Will the clusters that are to be invoked await?
    let awaits = metadata
        .node()
        .invoke(&req, &exchange.accessor()?)
        .any(|item| {
            item.map(|(cmd, _)| self.handler.invoke_awaits(&cmd))
                .unwrap_or(false)
        });

    if awaits {
        // Yes, they will
        // Allocate a separate RX buffer then and copy the RX packet 
        // into this buffer, so as not to hold on to the transport layer
        // (single) RX packet for too long and block send / receive 
        // for everybody
        let Some(rx) = self.rx_buffer(exchange).await? else {
            // Allocating an RX buffer failed. 
            // However, `rx_buffer` already had sent a status response 
            // "Busy" to the remote peer. We can therefore simply unroll 
            // our stack by returning.
            return Ok(());
        };

        // Re-parse the incoming request
        let req = InvReq::from_tlv(&get_root_node_struct(&rx)?)?;

        // Call the clusters and at the same time populate our TX
        // buffer
        req.respond(&self.handler, exchange, &metadata.node(), &mut wb)
            .await?;
    } else {
        // No, they won't. Answer the invoke requests by directly using
        // the RX packet of the transport layer, as the operation won't await
        // Same as per above, call the clusters and at the same time
        // populate our TX buffer
        req.respond(&self.handler, exchange, &metadata.node(), &mut wb)
            .await?;
    }

    // Now that the clusters are invoked and we have their response in `wb`,
    // call the transport (exchange) layer to send the response
    // 
    // Note that `exchange.send` will NOT complete until it receives an
    // ACK for the message it sends. Therefore, it might transmit our
    // `wb.as_slice()` payload multiple times, with multiple messages
    // But we don't care about that. Thanks to `async`, this re-transmission
    // loop is hidden from us. All that we need to provide is the message
    // payload in an idempotent way (as a `&[u8]` slice in this case 
    // that can be read from multiple times), so that the transport layer
    // can do its re-transmission logic.
    exchange.send(OpCode::InvokeResponse, wb.as_slice()).await?;

    Ok(())
}
```

`self.tx_buffer(exchange)` and `self.rx_buffer(exchange)` are also interesting, as these are `async` calls, and in fact, allocating an intermediate TX or RX buffers can fail. Here's the TX buffer allocation:
```rust=
async fn tx_buffer(&self, exchange: &mut Exchange<'_>) -> Result<Option<B::Buffer<'a>>, Error> {
    if let Some(mut buffer) = self.buffers.get().await {
        // Getting a TX buffer (potentially after some time!) succeeded
        // Size it and return it.
        // 
        // NOTE: How much (and even if) allocating a buffer can await
        // for a free buffer is up to the `BufferAccess` implementation,
        // but it should be in the order of a few milliseconds, as 
        // while awaiting here we are potentially blocking the single
        // RX/TX buffers of the transport layer.
        //
        // The default `BufferAccess` impl does not await.
        buffer.resize_default(MAX_EXCHANGE_TX_BUF_SIZE).unwrap();

        Ok(Some(buffer))
    } else {
        // Getting a TX buffer failed.
        // 
        // Before returning, call `send_status` (the method we looked at
        // during the examination of the "Timed" req handling)
        // to return to the client a status code that we are "Busy" 
        // (i.e. it should retry later, when we might have buffers)
        Self::send_status(exchange, IMStatusCode::Busy).await?;

        // Return `None` so that the upper function can unroll its stack
        Ok(None)
    }
}
```

## Issue 4: Responding to exchanges is "locked" and hard-coded inside the transport layer implementation

Method `Matter::run` currently is not only running the exchanges' transport logic (as in dispatching RX packets to `Exchange` objects and sending their TX packets). It is also managing the lifecycle of all "responder" exchanges and keeps them locked in a cage.

Worse, the _concrete_ IM and SC implementations of the upper layers [are hard-coded](https://github.com/project-chip/rs-matter/blob/main/rs-matter/src/transport/core.rs#L352).

### Solution

While we can implement a "callback / handler style" API so that the user can plug-in their own protocol handlers, that might not be the best _base-level_ API, as it - by necessity - would hard-code how multiple exchanges are executed _concurrently_ (i.e. their execution and lifecycle model). Also it is not quite an idiomatic Rust, which seems to favor a non-closure based, "external iteration" style base-level APIs, and then optionally provide closure/handler API on top of the base-level ones.

(Also there is the question of how do we create "initiator" exchanges, that we need for handling subscriptions which is addressed in the next issue.)

Instead of a callback/handler API, the base-level "responder" exchange API for the upper layer is as follows:
* [`let exchange = Exchange::accept(&matter).await`](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/transport/exchange.rs#L739)
  * ...where `&matter` is a reference to a `Matter` instance
  * This would wait until a new exchange is initiated by a remote peer, and then that exchange would be returned to the upper layer / user code
  * Obviously, multiple async tasks (or futures aggregated in a bigger future) can concurrently call `Exchange::accept`; the more tasks/futures do that "in parallel", the more exchanges would be handled "simultaneously" (w.r.t. IO, as everything is dispatched off from a single thread still)
  * Also obviously, somebody needs to run in another task/future `Matter::run` or else the Matter transport layer will not run, and therefore no responder exchanges would ever be created, as there would be no networking traffic

#### Users just want to run their on-off cluster, not deal with the complexity of accepting responder exchanges!

Sure, and for this we still have "cage" callback-style utilities built on top of the above base-level API, thanks to the new `async-fn-in-trait` functionality in Rust:

* [`Responder::run`](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/respond.rs#L120), which takes a `&matter` reference and organizes a pool of "handler" futures to concurrently call `Exchange::accept(&matter)` and then apply on each accepted exchange a user-provided `ExchangeHandler` trait callback 
  * `DataModel` and `SecureChannel` are retrofitted to implement the single-method `ExchangeHandler::handle(&mut Exchange)` API and are thus "exchange handlers"
* [`DefaultResponder`](https://github.com/ivmarkov/rs-matter/blob/next/rs-matter/src/respond.rs#L229), which internally uses `Responder` from above with an `ExchangeHandler` instance which is a composition of the default `DataModel` and `SecureChannel` protocol handlers

The key difference between this new and the old arrangment being that `Responder` and `DefaultResponder` - just like `DataModel` and `SecureChannel` are **not** part of the main `Matter` instance and as such are replaceable with equivalents by the user.

... which brings the question of _what are the roles and respoonsibilities of the `Matter` object then_, which is discussed in [Issue 8](#issue-8-current-exchange--transport-code-is-all-over-the-place).

## Issue 5: No way to initiate an exchange

As per above, we do need this so as to implement reporting data on active Interaction Model subscriptions.

### Solution

Similarly to `Exchange::accept`, the improved exchange layer now has `Exchange::initiate`:
* Call `let exchange = Exchange::initiate(&matter, node_id, is_secure)`
 * This would create a new initiator exchange, as long as there is a valid session (of the provided type) with the node whose ID is provided, or fail otherwise
 * Initiating an exchange to a node with which we don't have a valid session yet is left for the future, as that would require implementing the client side of the Secure Channel protocol

## Issue 6: Robust error handling

The current exchange layer is not really behaving well with regards to error conditions. The error conditions that need to be handled:
* a) A new responder exchange was created successfully, however it is not getting accepted by anybody because there are not enough exchange handlers in e.g. the upper layer
* b) A responder or initiator exchange fails "mid-flight" after sending and/or receiving some message(s). Or the user code holding an `Exchange` object fails due to some other error unrelated to Matter. In any case, the user code stack that uses the `Exchange` instance is unrolled, and as a result, the `Exchange` instance is dropped!
* c) A new responder or initiator exchange cannot be even created because the transport layer had ran out of `ExchangeState` exchange slots (which track the MRP and the exchange role)
* d) A new responder exchange was created successfully, yet the upper layers find out they are out of resources (say, not enough memory or other resource)

### Solution

To bring some order in the error handling process, the improved transport/exchange layer distinguishes between two main states an exchange could be:

#### State 1: Exchange is "owned" by the transport layer itself

What this means is that the internal structure in the transport layer that tracks the exchange (`ExchangeState` - see below) is created, however:
* (`Role::Responder(ResponderState::AcceptPending)`): The actual `Exchange` object that is used by the upper layers is either not created yet (by somebody in the upper layers completing an `Exchange::accept().await` call for that exchange)...
  * This is error condition (a) from above
* (`Role::Responder(ResponderState::Dropped)` and `Role::Initiator(InitiatorState::Dropped)`) ...or the `Exchange` object was dropped after being created (and after possibly being used). This case can happen for both initiator and responder exchanges and in fact *will always happen* for every single exchange, as all `Exchange` objects are dropped sooner or later
  * This is error condition (b) from above, which might actually not be an error condition even, but a normal exchange completion
* (No `Role` instance, no `ExchangeState` instance): It might also happen that the transport layer cannot even create its own `ExchangeState` structure instance for an RX packet that looks like a new exchange, as it had ran out of `ExchangeState` exchange slots for that session (by default, they are up to 5 per session, as suggested by the Matter spec)
  * This is error condition (c) from above

What is important for State 1 is that in State 1 it is the _transport layer_ who is _ultimately responsible_ for somehow handling the error conditions and ultimately completing the exchange, possibly by even responding itself to the peer that initiated the exchange.

The TL;DR for how the transport layer handles exchanges it owns is that the only thing it does is nothing more than to **close the Exchange by following the "Closing an Exchange" procedure in the Matter spec**.

In details:
* For issue (a): if the new exchange is not accepted within 500ms, the exchange is closed as per the "Closing an Exchange" procedure in the Matter spec - i.e., a Standalone ACK is sent if one was not sent yet and that's it - the `ExchangeState` instance is removed and the exchange slot in the session is free'd
* For issue (b): 
  * If the exchange has no "in-flight" re-transmission, then the exchange is closed just like when handling issue (a) except without any delays
  * If the exchange has an "in-flight" retransmission of a reliable message which is not yet ACKed by the remote peer, **the whole session is closed abruptly** by sending a SC `CloseSession` status non-reliable message. The transport layer really cannot recover better from that case, as it does not have the payload of the message which is in a re-transmission state in the first place! (As the transport layer is operating off from a single shared with everybody TX buffer after all)
* For issue (c):
  * Exactly as in issue (a) - send (via using the RX buffer that is locked by the transport layer in that case but so what!) an ACK if the exchange has an outstanding ACK waiting and then remove the `ExchangeState` object

#### State 2: Exchange is "owned" by the upper layer

`Role::Responder(ResponderState::Owned)` and `Role::Initiator(InitiatorState::Owned)`)

What this means is that the `Exchange` object for the particular exchange was created successfully by the upper layer (with `Exchange::accept` or `Exchange::initiate`) and is still alive (not dropped).

In that state, the only message that the transport layer generates on its own for a particular exchange is a Standalone ACK after a timeout, or when receiving a duplicate packet due to the other peer re-transmitting. All other RX/TX is only done when the upper layer explicitly uses the send/receive functions on the `Exchange` object.

_Any_ errors (except network failures) that might happen during the RX/TX of messages in this state _are reported back to the upper layer code_ as an `Error` code which is returned from the sending/receiving methods of the `Exchange` struct. The thing is, if the upper layer code cannot deal with those, or if it cannot deal with any _other_ error conditions stemming from elsewhere (like it being low on resources), it would eventually unroll its stack, thus dropping the `Exchange` object, and thus transferring the ownership of the exchange back to the transport layer! That would mean that the exchange would enter State 1 again, and will be completed by the transport layer, following the above rules.

#### But handling of "low on resources" conditions and other errors should be more intelligent, at least most of the time!

I.e. rather than just ACKing and then silently closing the exchange leaving the remote peer maybe waiting for a response by us, and timing out the exchange after a long time, we should ideally be sending:
* SC BUSY status code for all Secure Channel payloads which try to initiate a Pase or Case session
* IM BUSY status code for all Interaction Model payloads which try to initiate a Read, Write or Invoke interaction
* IM "Resource Exhausted" status code for all Interaction Model payloads which try to initiate a Subscribe interaction
* IM Failure for all other incoming requests which look like an exchange which is "mid-flight" yet they are unexpected by the Interaction Model layer

This is a fair statement, however it is questionable whether it is the duty of the transport layer to do this, as it does _not_ understand IM or SC protocols' details. Moreover, some of the above messages need to be send in a reliable manner with (re)transmission, which is difficult to do from within the transport layer "inner guts" itself.

In general, the transport layer only understands:
* `MRPStandaloneAck`
* SC `CloseSession` status code
* (In future) Session counters sync req/resp messages

So this problem is solved in a different way, as part of the upper layers:
* In addition to having `DataModel` and `SecureChannel`, the `rs-matter` framework now offers two additional `ExchangeHandler` implementations:
  * `BusyDataModel`
  * `BusySecureChannel`
* These handlers are very simple - they send `Busy` to the incoming messages that are the opening ones for a responder exchange, and `Failure` for everything else. Being so simple, these handlers don't need any additional buffers and _operate off completely from the transport layer RX/TX buffers_. What this means is that when these busy handlers are wrapped in a `Responder`, the `Responder` instance can create _a lot_ of handling futures for these, as they take so little memory, so that almost every exchange which is not handled by the main handlers, would be answered with a small delay by the busy handlers.
* Finally, the `DefaultHandler` struct mentioned in [Issue 4](#issue-4-responding-to-exchanges-is-locked-and-hard-coded-inside-the-transport-layer-implementation) actually runs _two_ `Responder` instances - the one which uses the "real" `DataModel` and `SecureChannel` handlers, and another one - answering with ~ 100ms delay - which runs the `BusyDataModel` and `BusySecureChannel` handlers. Thus - and in a natural way - if the main responder is low on resources and cannot (or is unwilling to) accept an exchange on time, the "busy" responder would kick in, answering with "Busy" or "Failure". Finally, if even the busy responder cannot handle the storm of exchanges, the transport layer would kick in after a ~ 500ms delay by ACKing the RX message for the exchange and then dropping the exchange slot from its session.

## Issue 7: Low level details revealed to upper layers

Currently, the IM and SC handler take an `Exchange` struct and then additionally - a pair of `&mut Packet<'_>` references for TX/RX.
This is not ideal, as the upper layers should not be concerned with the low level details of the transport layer packet structure. Ideally, they should:
* Have a way to read (for RX) or create (for TX) the message payload (TLV or other), where the RX payload is already decoded (decrypted) by the transport layer, and the TX payload would be automatically and transparently encoded (encrypted) by the transport layer
* Have a way to specify the protocol ID and the protocol OpCode
* Indicate if the message is reliable or not

### Solution

Instead of dealing with a `Packet` structure, the upper layers know about:
* An `MessageMeta` structure, that only captures the protocol ID, the protocol Opcode and whether the message is reliable or not
* A `[u8]` slice for the RX payload
* A `&mut [u8]` slice for the un-encoded TX payload they have to build (and then return the stanrt and end of the payload as well as the message meta-data)

For presenting these types of structures to the upper layers, as well as - and more importantly - for solving [Issue 2](#issue-2-too-many-rxtx-buffers), the transport layer **no longer has the notion of a `Packet` structure**. Instead, it only has the notion of a packet _header_ structure (`PacketHdr` which is just a concatenation of a `PlainHdr` and `ProtoHdr`) as well as utility methods on `PacketHdr` for decoding / encoding a packet from/to _user supplied_ `ParseBuf` and `WriteBuf` respecitvely.

This gives us the freedom to encode / decode the final UDP/TCP/etc packet either in-place, in an owned `heapless::Vec`, or elsewhere.

## Issue 8: Current exchange / transport code is all over the place

Or in more details:
* There is no `ExchangeMgr`. Exchange slots are owned directly by the `Matter` object
* All transport code is implemented directly on the `Matter` object, albeit in the `transport` module. So the `Matter` object currently has two implementations: one in `rs_matter::core`, and then another - in `rs_matter::transport::core`, which is weird, but acceptable in Rust

### Solution

The code is (re)organized as follows:
* `TransportMgr` is back! 
  * It is owned by the `Matter` object and aggregates all transport layer code; lives in `rs_matter::transport::core`
  * `TransportMgr` - in turn - now owns `SessionMgr`, as sessions are part of the transport layer
  * There is no a separate `ExchangeMgr`. The exchange slots are **not** owned by any `*Mgr`. They are owned and managed by their `Session` instance instead. Each session can have up to `MAX_EXCHANGES` exchange slots, which is by default set to 5 (as per the suggested maximum in the Matter spec). Regardless, `TransportMgr` is intimately aware about the notion of an exchange, as well as the notion of sessions (via its aggregated `SessionMgr` instance)
  * `TransportMgr` now also owns the `MdnsImpl` which is the mDNS service in use by the Matter stack, as it is also considered a part odf the tranport layer
  * The `Exchange` struct which is the main interface to the transport layer for the upper layers / user code lives in `rs_matter::transport::exchange` as before. There is now also `MessageMeta` (as per [Issue 7](#issue-7-low-level-details-revealed-to-upper-layers)), `ExchangeId` (an internal ID of each exchange - a concatenation of the internal session ID and the exchange index in the slots' array of the `Session`) as well as internal, transport-layer-only structs, like `ExchangeState` (the exchange slot, used to be called `ExchangeCtx`), `Role` and a few others
* `TransportMgr`'s responsibilities are as follows:
  * Run the network layer, via `TransportMgr::run` and `TransportMgr::run_builtin_mdns`
  * Provide means for the upper layers to accept and initiate exchanges (via `TransportMgr::accept` and `TransportMgr::initiate` which are crate-public and exposed via `Exchange::accept` and `Exchange::initiate` instead)

Since `TransportMgr` is an internal detail of the `Matter` object, its crate-public `run`, `run_builtin_mdns`, `accept` and `initiate` methods are exposed either on the `Matter` object or on the `Exchange` object as well, as public methods.

### What is the `Matter` object responsible for, in the end?

Clear:
* Aggregating the transport layer, and exposing it to SC and IM protocol handlers via a handful of structures and methods: `Exchange`, `Matter::run`, `Matter::run_builtin_mdns`
* Providing the `rand` and `epoch` functions

Unclear:
* Providing basic configuration in the form of `BasicClusterInfo` (TBD: do we still need this as part of the `Matter` object)
* Providing the notion of fabrics, in the form of `FabricMgr` (TBD: do we need to publicly expose this?)
* Providing the notion of IM ACLs, in the form of `AclMgr` (TBD: shouldn't it be owned by the `DataModel` IM implementation?)
* `PaseMgr` (TBD: Should this be part of the transport layer?)

### What the `Matter` object should NOT be responsible for, in the end?

Clear:
* Not responsible or aware of the Interaction Model layer, its payload / details (but the Interaction Model is aware of `Matter` and its transport layer - via a well defined small set of public exchange APIs, as per above)
* Not responsible or aware of the Secure Channel layer, its payload / details, except for a handful of messages related to session management and packet re-transmission (but the Secure Channel is aware of `Matter` and its transport layer - via a well defined small set of public exchange APIs, as per above)
* Not responsible for organizing in any way the response to exchanges. This is the role of the `Responder` utility, or user-defined exchange processing, using "real" async executors like `tokio` etc.
* Not responsible for organizing in any way initiation of exchanges

## Appendix A: Undefined Behavior In Current `Exchange` Impl

(Hold tight, this is a bit long and tricky.)

The underlying transport implementation below the `Exchange` API currently implements the following metaphor (only receiving will be examined here, but sending has similar issues):
* For each active exchange, the user owns an RX packet/buffer. How and where this packet is allocated is not a concern of the Exchange API.
* The user operates on this buffer freely (as in mainly reading from it of course)
* When the user wants to receive, the user calls `Exchange::recv(&mut rx).await` or `Exchange::exchange(&mut tx, &mut rx).await`, supplying a *mutable reference* to the RX buffer.
* [The code for the above implementation uses `unsafe` to avoid lifetime-related compiler errors](https://github.com/project-chip/rs-matter/blob/main/rs-matter/src/transport/core.rs#L424), as the above pattern is un-expressible with the existing Rust lifetime rules. This is really important: should we've NOT used `unsafe`, this pattern would've been impossible to implement, and the problem would've not been here in the first place!
* This mutable RX reference - together with a `*mut` ref to the `async` Notification primitive owned by the concrete `Exchange` instance is recorded in an internal central singleton structure (the Matter transport impl), and when a packet for that particular exchange arrives, it is copied into the recorded RX buffer *mutable reference*, and then the corresponding `Exchange` object is awoken from `await`-ing, by `signal`-ing the recorded `*mut` ref of the `Notification` structure.

... and that's the crux of the issue - that the mutable RX reference and the mutable Notification object reference "are recorded", i.e. they are kept around **accross** await points! 

This can lead to crashes - i.e. what happens if the `Exchange` instance had given the `*mut` refs of the user's RX buffer and its `Notification` instance to the internal transport impl, is now `await`-ing, and the user just "cancels" the `await` "mid-flight" by stopping to poll the future?

If the cancellation of the future (which means the future is just dropped or forgotten) calls the exchange `drop` destructor - all is right - the `*mut` references will be de-registered from the internal transport impl, so no dangling references to memory which might no longer be around.

The problem is when the user `core::mem::forget`s the future or some of its parent futures (forgetting in Rust IS a safe API!). Or uses `Arc`/`Rc`s that end up with cycles which leads to memory leaks as well. In that case, the compiler would think the RX packet specifically no longer has a mutable reference and it can be e.g. dropped (or mutated freely by somebody else), yet that's not the case, as a `*mut` reference to the RX packet is still registered in the transport impl!

Now, I do realize this all spounds a bit long, unclear, theoretical and a corner case, stemming from the fact that Rust destructors are currently not guaranteed to run (the so called "leakpocalypse" discussion that had happened ~ 2015), but the problem is in there, real. We were recently hit by it in `esp-idf-hal` in two separate places by that very same problem (SPI driver with DMA; non-`'static` closures passed to hidden OS threads) and one of these places was found by users, not us.

Anyway, the solution is to have the RX buffer owned by the internal transport impl. NOT by the user and NOT by the concrete `Exchange` instance. This way, no `*mut` pointer with unknown lifetime is used accross await points. If the user wants a copy of the RX packet in its own buffer, that's still possible, but the internal transport impl does not "record" the mut ref to the user's packet anywhere - it first receives the data in its own internal buffer, and only when the data is in there, it copies it to the user buffer, without keeping the mut ref around.

## Appendix B: (Digression) Do we need the Data Model handlers to be `async` in the first place?

Imagine that the HAL layer is actually _not_ requiring `await`s. I would say this might in fact be the norm rather than the exception for typical IO devices. Matter clusters seem to be semantically organized in such a way, that in fact no HAL `await` is necessary:
* When an on-off cluster is reporting its state, it is reporting its _current_ state, which requires e.g. a non-blocking read of an input pin. It is not awaiting anything
* When an on-off cluster is supposed to toggle from "on" to "off" or the other way around, it is setting an output pin to "high" or "low" without "waiting" for anything else
* When a window blinds cluster receives an "open" command, the semantics of that command is **not** that we should reply to that command only when the blinds are completely opened 20 or so seconds later. The semantics is that we should _turn on_ the blinds' motor and then reply immediately. Which is also e.g. setting an output pin to "high" and then responding the IM command without `await`-ing anything. In other words, the command is just "_start_ opening", not "start opening and wait with the command response until the blinds are opened completely"
* Ditto for reading the current state of the window blinds - we are supposed to report the current opening/closing _progress_ (as in e.g. "50% opened")
* Ditto for complex clusters like the multimedia ones

Does that mean that we should retire our `async` [`AsyncHandler` Data Model trait](https://github.com/project-chip/rs-matter/blob/main/rs-matter/src/data_model/objects/handler.rs#L299) and only support [the non-`async` `Handler` one](https://github.com/project-chip/rs-matter/blob/main/rs-matter/src/data_model/objects/handler.rs#L35)? 
No because we might have a HAL that is really much easier to express with `await`-ing. Imagine a Matter bridge device that communicates with the non-Matter devices it is bridging over the network. It is very attractice and simple to have the possibility of e.g. an `async` `AsyncHandler::invoke` on-off cluster implementation, that - while inside the `invoke` method - opens an HTTP REST request to the remove device, sends the request using `async` IO and awaits the `200 OK` response using `async` IO. Contrast this with a complex caching logic where you need to notify an interim layer that it needs to - at some point - send an HTTP request; and then we would be reporting back "the light went on" even if - in fact - it *didn't*, due to the device being temporarily offline or whatever. (Not that some Matter controllers don't operate like that anyway! :) )

So in conclusion, I think we have to preserve the current asynchronous `AsyncHandler` contract, as it is a superset of what the user might actually need. If we ~~(ever)~~ (UPDATE: I did) implement an intelligent buffer management scheme in the Interaction Model, we might introduce a new set of methods in the `AsyncHandler` trait: `AsyncHandler::xxx_awaits(&self) -> bool`. This way the user would be able to indicate if their cluster(s) are really needing asynchrony - and if not - the Interaction Layer might use this information to skip on using extra buffers for sending. For one, all clusters in Endpoint 0 are purely computational (just like the whole Secure Channel impl), so they do not really need an extra TX buffer. Or even an extra RX buffer, for that matter.

## Appendix C: High level summary of code changes

This is a non-exhaustive summary of the changes accompanying this RFC.
All changes are avilable in a branch [here](https://github.com/ivmarkov/rs-matter/tree/next).

#### New modules / types (or existing ones which were almost re-written)

Transport layer:
* [`rs_matter::transport::core::*`]
  * All transport code is re-assembled under a new `TransportMgr` type. Heavily modified so better to assume it is brand new
* [`rs_matter::transport::exchange::*`]
  * This is the improved `Exchange` instance and all acompanying types, like `ExchangeId`, `RxMessage`, `TxMessage`, `MessageMeta`. A lot of these types are brand new, or so modified in terms of impl as if these are brand new

Exchange responders / exchange handlers:
* [`rs_matter::responder::Responder`]
  * A generic way to respond/accept multiple incoming exchanges simultaneously without using async executor and utilizing only intra-task concurrency (i.e. `select`/`join`). Responders need an `ExchangeHandler` instance so as to apply it to the incoming exchanges.
* [`rs_matter::responder::ExchangeHandler`] - and its composition - `CompositeExchangeHandler`
  * Something that can handle exchanges. Intuitively, this is a protocol handler, like the ones for IM and SC. `DataModel` and `SecureChannel` - the two protocol handlers provided by `rs-matter` out of the box implement the simplistic `ExchangeHandler` contract.
* [`rs_matter::responder::DefaultResponder`]
  * "Out of the box" composition of the IM and secure channel implementations in `rs-matter` into an exchange responder.

IM / SecureChannel:
* [`rs_matter::interaction_model::busy::BusyInteractionModel`]
  * A very simple Interaction Model implementation that answers with an IM Status Code `Busy` to every incoming request that initiates a new exchange.
* [`rs_matter::secure_channel::busy::BusySecureChannel`]
  * Ditto, but for Secure Channel.

Utilities:
* [`rs_matter::utils::signal::Signal`]
  * A new async primitive. Used directly in the `Subscriptions` implementation of IM subscriptions, and indirectly - by `Notification` and `IfMutex`
* [`rs_matter::utils::notification::Notification`]
  * A `Notification` primitive which used to be based on `embassy_sync::Signal` and is now based on our own `utils::signal::Signal`. Implementation details not so important as the new and the impls behave identically
* [`rs_matter::utils::ifmutex::IfMutex`]
  * An `IfMutex` primitive which is essentially an asynchronous mutex, except slightly more powerful than the `embassy_sync::Mutex` primitive after which it is modeled, in that `IfMutex` can conditionally lock the mutex, unlike its `embassy_sync::Mutex` counterpart
* [`rs_matter::utils::buf::BufferAccess`], [`rs_matter::utils::buf::PooledBuffers`]
  * `BufferAccess` is a trait for a "slab" allocator that can allocate memory of the same size and shape. Asynchronous (i.e. depending on the implementation, calling code might await until a buffer is available)
  * `PooledBuffers` is a simple implementation of the `BufferAccess` contract that allocates memory from a fixed, pre-allocated pool (i.e. no heap operations).

#### Heavily modified modules / types

Transport layer:
* [`rs_matter::transport::packet::*`]
  * The notion of a packet header is now disconnected from the notion of a (decoded or encoded) packet payload.
  * What this means is that the packet proto and plain headers can now be decoded/encoded from/to any container, where the container is still represented by a `WriteBuf` / `ParseBuf`, except that these instances are taken during encoding / decoding as method _parameters_. In the past, the `Packet` struct (which no longer ecists and is superceded by the `PacketHdr` struct) always assumed that the payload is encoded/decoded in a pair of `WriteBuf`/`ParseBuf` instances which were **owned** by the `Packet` struct. This - in turn - introduced lifetime issues when we switched to a single pair of RX + TX packets owned by the `TransportMgr` instance.

IM layer:
* `rs_matter::data_model::core::DataModel`
  * Modified so as to support subscriptions (new struct - `Subscriptions`)
  * Modified to support better buffer utilization:
    * Interactions that don't need TX or RX buffers (like timeout request/response) don't request these buffers
    * Interactions that only involve non-awaiting clusters don't need and use an extra RX buffer (as these interactions don't await)

Secure Channel layer:
* `Case`, `Pake` - modified so as _not_ to need additional `&mut [u8]`-shaped buffers
* Modified not to need `CaseSession`. All session state is kept in a regular `Session` instance which gets reserved prior to the exchange beginning
* Still pending for a future PR is an optimization of the other buffers it still uses

IM Integration tests' `ImEngine`:
* These tests are now more end-to-end - meaning - both sides (the initiator and the responder) use the Matter transport layer
* The communication is organized as two separate `Matter` instances, where the "remote" one is the "server" or the "device", and the "local" one is the client
* TBD: We have to decide what to do with the IM layer integration tests. I'm kind of drifting these towards end to end tests, but the opposite is a completely valid direction as well - we might decide to move these back into unit tests that live inside the `rs_matter::data_model` module and only know / test the `DataModel` layer

#### Slightly modified modules / types

* `rs_matter::core::Matter`
  * New methods, `reset`, `run` and `run_builtin_mdns` which delegate to `TransportMgr`

* `rs_matter::data_model::objects::AsyncHandler`
  * New functions which return `true` by default - `read_awaits`, `write_awaits` and `invoke_awaits`

* `rs_matter::data_model::objects::HandlerCompat` (mapping of non-awaiting `Handler` to `AsyncHandler`)
  * New functions which return `false` by default - `read_awaits`, `write_awaits` and `invoke_awaits`

* `rs_matter::data_model::objects::Node`
  * `read` method adjusted to take `ReportDataReq` enum, which is an enum that represents either a read request, or a subscribe request

* `rs_matter::mdns::builtin::MdnsImpl`
  * Changes due to `BufferAccess` now being generic on the type of buffer it offers

* `rs_matter::transport::network::Address`
  * Now capable of modeling TCP transport addresses; the transport layer is adjusted so as not to retransmit messages when these are sent over a reliable protocol
  * Note that a TCP-based implementation of `NetworkSend` and `NetworkReceive` is still pending though, but that's external to the core Matter transport impl, which should now (in theory) work over reliable transports as well

* `BufferAccess`
  * Buffer type generified (could be an e.g. `&mut [u8]`, or a `&mut heapless::Vec<u8, N>` or something else)

* `EitherUnwrap`
  * Renamed to `Coalesce` and can now be used with `join*` in addition to `select*` future combinators