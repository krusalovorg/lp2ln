# Proposed Flow Protocol for F2 and M1

**Status** The direct F2/F3/M1 preview is implemented under opt-in ALPN lp2ln-flow/1. This is a local preview profile. [Implemented interface and guarantees](#direct-preview-implementation), [security review](F2_SECURITY_REVIEW.md) and [validation status](PROGRESS.md).

## API and ownership

```rust
pub enum Profile { Reliable, Realtime, BestEffort, Bulk }

pub struct Requirements {
    pub profile: Profile,
    pub delivery: Delivery,
    pub ordering: Ordering,
    pub priority: u8,
    pub max_queue_age: Duration,
    pub max_age: Option<Duration>,
    pub max_pending_bytes: usize,
    pub max_payload: usize,
    pub target_rate_bps: Option<u64>,
    pub paths: PathPolicy,
}

// Illustrative signatures are shown at the call site.
let flow = node.flows().open(peer, protocol, requirements).await?;
let accepted = flow.try_send(bytes, created_at, ttl)?;
let incoming = flow.receive().await?;
```

- A `Link` is a connection to one authenticated adjacent peer with an implementation-owned handle and local connection epoch. A `Path` is a validated sequence of links to an authenticated destination. Path identity is local and includes network generation. M1 uses one direct Link per path.
- A `FlowID` is a 128-bit initiator-generated random identifier scoped to authenticated endpoint identities and the local namespace. `FlowOpen` carries epoch, protocol and requested capabilities. `FlowAccept` confirms the agreed requirements and both IDs. Open/accept and close are idempotent and replay-protected. The handle lifetime manages admission, cancellation and ownership in both directions. A later path switch preserves logical FlowID and its end-to-end nonce/replay state.
- Embedded Rust uses `NodeRuntime::flows()`. Register a protocol and its admission policy. Opening fails explicitly with UnsupportedDelivery, PeerUnsupported, NoCompatiblePath, TooLarge, QuotaExceeded, QueueFull or Expired. Local `Accepted` means queued under a documented contract. A receiving observation or reliable protocol ACK has a separate identifier. Reliable send fails on closed paths during M1. Future resume needs its own acknowledgement and duplicate semantics.
- `FlowLink` is an optional extension to the existing session abstraction with negotiated datagram support, stream capabilities, effective payload cap, link validation, congestion telemetry and close events. Existing objects return unsupported by default. Keep the legacy stream and packet wire available. Negotiate Flow capability over an authenticated control channel before enabling the new wire; application events start after verification on both sides.
- Mandatory M1 support is unordered Realtime with expiry and Reliable ordered control. Profiles define defaults independently of carriers. Bulk priority and BestEffort can share machinery when negotiated. Return unsupported for unimplemented reliability/ordering combinations, including reliable unordered and partially reliable delivery.

## F2 identity and encryption

1. **Link authentication.** After QUIC/TLS transport setup, bind a fresh bidirectional signed challenge to the expected LP2LN Peer IDs, roles, both nonces, network protocol version, negotiated capability digest and context-specific TLS exporter. Both sides match the same handshake context. Fail closed on missing identity, role/capability mismatch, shared-secret/channel mismatch or timeout. Reserve separate limits for unauthenticated connections and messages. Use a dedicated exporter label, authenticate both complete capability offers and verify TLS proof of key possession on the F2 path. The current legacy QUIC verifier is not proof of LP2LN identity. Do not mark the connection ready based on ingress counts.
2. **Endpoint authentication and ephemeral agreement.** Evaluate `Noise_XX_25519_ChaChaPoly_SHA256` using reviewed `snow` interoperability and official test vectors. Each known LP2LN identity signs a versioned binding to its separate Noise static public key and allowed role, with purpose and expiry. Exchange this binding inside the protected Noise handshake payload, check the key against the Noise remote static key and compare the Peer ID to the expected remote identity. Bind endpoints, Flow protocol/suites, challenge and connection roles to the agreed transcript/prologue. An explicit E2E key-confirmation exchange precedes application traffic. The E2E transcript excludes per-link TLS exporters and keeps path changes out of the endpoint key schedule. Remove ephemeral handshake secrets as soon as possible. F2 code review must verify protocol context binding, implementation support and key pinning/rotation.
3. **Record layer.** Use Noise's library-provided stateless transport mode for authenticated unordered records. Use a single 64-bit packet nonce counter per direction per key epoch across all flows that share keys. Burn allocated nonces on cancellation. Independent per-flow key domains need separate Noise contexts or a reviewed implementation and vectors. Record any logical ordering position separately. Maintain a bounded sliding replay window per endpoint session and epoch. Check the AEAD before committing sequence or creating any flow state. Duplicate/late checks use bounded state. Noise reserves the highest nonce value. Rotate by starting a fresh authenticated handshake well below the limit, use a short bounded overlap and discard retired keys after the transition.
4. **Wire context.** The short outer version, session identifier and nonce serve only as lookup hints. Bind or repeat routing-independent version, session/epoch, direction, FlowID, frame kind, sequence, flags and deadline in the authenticated Noise message. Compare the protected values before dispatch. Mutable route information uses hop-level integrity and is never trusted as endpoint identity. M1 has no 0-RTT FlowOpen, data or relay admission. Session restart uses fresh keys and IDs.
5. **Compatibility.** V3/V4 remain legacy capability. An authenticated peer that cannot agree on the new protocol receives a capability error. Temporary debug overrides and permissive packet settings do not grant access to Flow ingress.

[Noise specification](https://noiseprotocol.org/noise.html) · [Snow stateless API](https://docs.rs/snow/latest/snow/struct.StatelessTransportState.html) · [QUIC TLS](https://www.rfc-editor.org/rfc/rfc9001.html)

## QUIC DATAGRAM and scheduling

- Extend current `QuicSession` rather than splitting the transport. Keep an independent reliable control stream and start a bounded DATAGRAM reader after link authentication. Configure negotiated send/receive limits, path MTU estimates and application caps. Query `max_datagram_size()` and subtract the measured framing overhead. First operator profile should start with application payloads at 1,000 B or smaller as path budgets require.
- Give realtime flows byte/item/per-peer limits. Use `Bytes` for ownership transfer where it eliminates copies. The producer's monotonic creation time determines expiry. Drop expired jobs at enqueue, queue timers, send admission and before authenticated receiver delivery. Emit structured drop reasons. Reserve bounded control service and schedule realtime by urgency plus fairness. Bulk receives the remaining pacing budget.
- End-to-end age requires a conservative authenticated offset bound and an explicit uncertainty state. Measure offset with a bidirectional timestamp exchange. After suspend, migration of a monotonic timebase or weak confidence, pause strict expiry delivery and renegotiate. A local send check and receiver age check serve distinct purposes.
- Call Quinn `send_datagram` after expiry and pacing checks, apply a shallow byte cap and sample buffer space. `send_datagram_wait` does not give deadline scheduling. Quinn may retain a submitted datagram until it can send it. M1 can guarantee the application receiver's age cutoff and its own queue behavior. A hard deadline on actual socket writes requires transport-level expiry support.
- Measure transport-admitted bytes, sender E2E sequence, unique authenticated receives, application-consumed/acknowledged IDs, jitter, goodput and queue ages. A dropped or oversize datagram never silently switches to an ordered retransmitting stream. Optional full-path probing and make-before-break come after direct M1.

[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) · [Quinn Connection](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html)

## Implementation order and gates

1. Add protocol transcript/wire vectors and an isolated handshake module. Compare expected/unexpected peers, mismatched exporters, swapped roles, corrupted Noise identity certification, incompatible versions, restart, duplicate and reordered records, expiry and rotation overlap.
2. Extend the existing link registry to publish verified capability state, then exercise the additive API against V3/V4 fixtures. Populate readiness from a verified challenge, including under stalled or pre-authenticated traffic.
3. Add QUIC DATAGRAM and independent reliable control with bounded queues. Reproduce duplex 50 PPS, load from bulk traffic and aged packets, both directions, on loopback and two devices.
4. Gate data delivery on authenticated protocol ownership, valid replay state and receiver age. Publish late/replay/overload metrics and ensure timers release buffers during idle periods and shutdown. Handoff, relay lease and media code are follow-on work.

## F1 handoff constraints for F2/M1

Reuse the node's scoped reservation mechanism when introducing typed Flow ingress. A verified Flow record must carry its reservation through authenticated application admission. Transfer ownership when the application receives the payload and distinguish refusal, expiration, replay, local queue admission and confirmed delivery. Legacy broadcast and IPC fanout expose best-effort behavior. A successful legacy writer or ring publication cannot serve as a Reliable Flow receipt.

F1 validation covers the managed native receive-credit contract, protected control admission and the failure test for reliable overload. Legacy author replay windows are path-agnostic and process-local. The Flow preview uses independent fresh endpoint sessions, bounded epoch overlap and authenticated nonce handling. Link exporter values belong to the hop proof only.

## Direct preview implementation

Enable the Flow ALPN with QuicTransportOptions.enable_realtime_flows. The acceptor explicitly calls NodeRuntime::authorize_realtime_peer with a pinned PeerId and application protocol. The dialer calls open_realtime_flow with the expected PeerId and direct endpoint. The receiver calls accept_realtime_flow. Both obtain the same FlowId and verified FlowLink. Flow::sender returns a cloneable admission handle, Flow::recv transfers an authenticated, unexpired Bytes payload, and Flow::rotate_keys triggers the authenticated rekey protocol from the initiator. Dropping Flow closes it. No fallback to a legacy connection occurs when Flow negotiation fails.

This preview supports unordered Realtime data, with an internal ordered protocol control stream. An application-controlled Reliable or Bulk Flow profile, per-record ACK, multipath and relays are deferred. Legacy bulk still works concurrently through the existing ALPN on the same listener. Metrics distinguish transport admission from authentication and application dequeue. A network datagram drop or Quinn receive eviction is observable as a gap to a sequence-aware application.

The application sets an absolute local monotonic deadline at most two seconds ahead. The receiver checks the conservative authenticated peer-clock bound before queue admission and again before handoff. Its bounded queue is reaped while idle. The checked clock bound is valid for at most five minutes or until the system clock no longer tracks the monotonic clock within the supported error. An initiator can renew it through key rotation. This is a conservative age policy for the preview, not a radio latency claim. The stream and native DATAGRAM buffers, pacing, path MTU check, node budgets and typed receive outcomes are part of the implementation.

[Quinn DATAGRAM API](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html) · [Noise framework](https://noiseprotocol.org/noise.html)

M2 extends Flow with an application-selected control exchange on the existing ordered stream, bounded to 512 B. Authenticated kind 5 uses the control nonce lane independently from kind 1 datagrams. Unsupported legacy applications do not send it. The RTC application protocol 0xff82 selects this facility. recv_with_deadline transfers the conservative local expiry alongside payload ownership. revoke_realtime_peer withdraws future admission. Fresh signed LAN hints are capped at 256 entries per query. Call semantics are specified in lp2ln-rtc and the Android M2 guide.
