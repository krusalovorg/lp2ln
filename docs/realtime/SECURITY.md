# Real-Time Security

## F0 wire contract

- V3 signs the ciphertext hash, endpoints, request/stream/protocol metadata and mutable hop fields. It is the legacy direct format. V4 signatures bind the immutable author fields while relays update hop metadata. A V3-only peer cannot verify V4, and V3 signatures cannot preserve signed hop fields across a hop mutation.
- Nodes that recognize V4 may learn a peer's support from a verified V4 signature. An operator can configure V4 when every hop supports it. A rotating or mixed-version mesh needs explicit compatibility tests and capability negotiation for new Flow traffic. F0 keeps both formats and the current behavior of deployed packet clients.
- A relay may neither assign an author's missing request ID nor alter its authenticated endpoints or ciphertext. An inbound session can learn a peer after a verified direct packet, while the origin of a forwarded packet does not establish an adjacent link identity.
- Replayed protected packets are discarded. Replays and authenticated relay duplicates do not count as malformed-frame strikes. The source/destination verification and accepted wire formats stay the same.
- Strict mode requires the legacy signature. It still uses a static ECDH payload key and a 128-position in-memory receive replay window. Outgoing persisted sequence ranges help sender restarts. A receiver restart and long-term key compromise are distinct risks and motivate F2.

## Limits and remaining gaps

The legacy decoded ingress count is a liveness hint. It cannot certify an expected peer or become a Flow path promotion signal. A permissive node can publish decrypted packets to the historical `subscribe_authenticated()` channel even though mandatory signature verification is disabled. Local protected data in this channel is useful in legacy clients. Its contract must stay distinct from strict Flow ingress.

Legacy chunk assembly can buffer frames before their auth checks and drops child signatures when assembling a packet. Resource limits now constrain this state. A future chunk protocol needs per-fragment validation and a clear assembly-authentication contract. The Android file-block path uses the block protocol rather than packet chunk reassembly.

Legacy QUIC currently accepts the server certificate without binding it to an expected identity. F2 must keep pre-authenticated links out of the application data path. QUIC TLS secures a hop. Relayed Flow data also needs endpoint encryption whose ephemeral keys are independent of routing.

Queue and session limits bound resource use at different layers. Upstream transport/broadcast queues, per-node total admission and the legacy Punch/STUN socket lifecycle need more work before Internet relay capacity targets. No runtime metrics imply that media is secure or that a route is eligible.

[Authenticated handshake proposal and security vectors](F2_M1_SPEC.md)

## Follow-up F2 gate

The legacy QUIC certificate verifier also accepts both CertificateVerify callbacks without checking the signature. Verified Flow links must require both TLS connection proof and the LP2LN identity proof over the connection's exporter. Legacy TLS certificate permissiveness, received traffic and transport addresses cannot create a Flow security context.

The [F2 security review](F2_SECURITY_REVIEW.md) defines separate link and endpoint trust, downgraded/failed negotiation, Noise XX and rekey invariants, and negative vectors. The F1 QUIC reordering fix keeps the existing replay window and wire protocols. F2/M1 production implementation is gated on shared ingress/fanout bounds and overload behavior. See [F1 limits](ARCHITECTURE.md#f1-follow-up-limits-and-failure-semantics).


## Direct preview security status

Flow uses the independent F2 context recorded in [the implemented security profile](F2_SECURITY_REVIEW.md#implemented-f2-profile). Legacy receiver replay state still resets on restart. The dedicated Flow ALPN and authenticated fresh endpoint IDs and keys isolate the new protocol from that legacy behavior. Direct preview testing covered the current implementation and reference vectors. Independent interoperability, mobile field validation and production rollout remain outside this checkpoint.
