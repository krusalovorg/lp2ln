# LP2LN Real-Time Roadmap

The [architecture audit](LP2LN_Real_Time_Architecture_Audit.md) records the source revisions and the original measurements. [Progress](PROGRESS.md) tracks implemented changes and release gates.

| Stage | Scope | Gate |
|---|---|---|
| F0 · P0 | Maintain the Android Core pin as the integration baseline. Define locally originated versus forwarded packet ownership, signature compatibility, request correlation and locked builds. | Strict V3 direct, strict V4 relay, restart sequence, content/DHT/discovery and Android file/chat checks pass. Confirm the new Core pin before rolling out the Android APK. |
| F1 · P0 | Bound legacy processor and writer queues, measure ingress stages and actual delivery, correct TCP framing latency symptoms and UDP receive ownership. | Count/byte and shutdown tests pass. Benchmark batches terminate and report their delivery observations. Add a shared byte budget through transport ingress, active processing and fanout, then run overload tests across file, chat, control and topology traffic. |
| F2 · P0 | Implement reviewed endpoint and link authentication with ephemeral session keys. | Identity, transcript, downgrade, replay, restart and key lifecycle vectors pass. Require F1 admission gate closure and the [F2 security review](F2_SECURITY_REVIEW.md) vectors. |
| F3 · P0 | Reuse existing discovery and candidate race for verified direct links. | Offline LAN with a stored address or QR. Require a correlated authenticated response from the expected peer before activating the link. |
| M1 · P0 | Add embedded Flow API and QUIC DATAGRAM carrier with bounded scheduling and authenticated delivery. | Two devices exchange duplex deadline-bearing data on a direct path while sharing the bottleneck with reliable traffic. |
| M2 · P0 | Add an application library and Android voice integration. | A 20-minute LAN voice call on two real devices, including screen-off and device lifecycle tests. |
| M3–M6 · P1 | Add optional relay admission, handoff, direct NAT traversal and hardware video. | Hold stable Flow IDs during validated path changes. Verify audio-first degradation before expansion. |
| L1–L5 · P2 | Multipath, other clients, resource integration, profile-guided performance and QoE. | Adopt optimizations against measured loss, latency, CPU, bandwidth and battery criteria. |

[Design proposal for F2/M1](F2_M1_SPEC.md) is the implementation starting point after the remaining F0/F1 checks are closed.

## Checkpoint before the direct Flow implementation

F1 has a scoped node ledger for managed frame allocation and compatibility handoff, plus ordered per-link receive authentication. The remaining F1 work is to integrate the bounded UDP listener inbox and aggregate native/Quinn credit, give verified control its bounded admission path, and exercise mixed file/chat/control overload with observable reliable outcomes. Track the receive-order performance cost and reclaim verification parallelism while retaining replay commit order. F2 follows those checks. F3/M1 still require F2 link and endpoint security before enabling QUIC DATAGRAM flow traffic. M2 depends on a working M1 on Android devices.

### Direct Flow checkpoint

The F1 managed ingress acceptance gate has a scoped implementation and regression coverage. F2 and the direct F3/M1 preview use the opt-in QUIC endpoint paths described in the specification. Two-device validation remains the release gate for the Android integration. Legacy receiver restart replay persistence and multipath performance are separate follow-ups. M2 needs the device harness to pass before integrating any media handling.
