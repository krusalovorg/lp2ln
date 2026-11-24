# Real-Time Implementation Progress

Snapshot from 24 November 2026.

## Integration bases

| Component | Selected base | Reason |
|---|---|---|
| Core | `65925aaf9b8faabfba4f9eaf607ac5eb8860e0cc` | Android's real git pin and the tip of `feature/p2p-sharing-20261109`. Includes both V4 relay/restart compatibility and reliable file-block routing on top of Core `main` `ea20401`. |
| Android | `fcd75b889f22729b22e58ff7504a3c7150013031` | Tip of `feature/lp2ln-file-transfer-performance`, descends from chat branch `14f3d3c` and Android `main` `f318110`. Each uses the same Core git pin. |

Fresh remote refs matched the audit. Earlier Core transport and topology branches remain separate. Core changes are on `feature/realtime-foundations`. Android changes are on `build/locked-rust-dependencies`. The latter keeps the published Core git dependency. An isolated path-dependency build exercises Android against the changed Core source until a new reference can be pinned.

## Completed changes

- **F0.** Corrected locally originated request-ID fixtures, explicitly reject an anonymous request ID during forwarding and preserve V4 author metadata on authenticated relays. Added strict direct and relay regression tests and leave old V3 direct sessions compatible.
- **F0.** Pinned the Rust toolchain and passed `--locked` in CI, Docker and Gradle. Core's vendored `h3-quinn` is a direct dependency so the patch applies when Core is consumed externally. Android's current published pin uses the same vendored package via a top-level patch. Quinn was aligned to 0.11.11 with a checked-in Android lock. The old Android host lock failed inside rustls-platform-verifier 0.4.0. The Core workspace lock also advances rfd to 0.15.4 because ashpd 0.9.2 failed to compile under the pinned compiler.
- **F1.** Added processor admission by count/bytes, room for small control candidates, deterministic drain, bounded writer queues and an aggregate chunk buffer cap. Split decoded, authenticated, locally accepted and subscriber-observed receive stages.
- **F1.** Moved default-processor relay dedup past authentication, corrected adjacent-peer bookkeeping and exercised replay/forgery regression behavior. Replaced the shared UDP receive race with a single socket owner and bounded inboxes. Added `TCP_NODELAY` and plain TCP vectored writes after measurement.
- **F1.** Matched benchmark IDs and payloads, added deadlines and instrumented queue wait, latency, jitter, goodput, observed loss and CPU. Android's file transfer fixture now waits for the actual TCP listener readiness event. This removes the same connection-refused race exposed by Android file and Core DHT tests. Neither production protocol needed a change for that race.
- **F2/M1.** [Technical specification](F2_M1_SPEC.md) prepared for design review.

## Verification

| Check | Result |
|---|---|
| Core workspace, Linux release | `cargo test --release --locked --workspace --no-fail-fast`. 257 passed, zero failures, one ignored doctest. Includes 130 Core unit tests, 14 characterization tests and the DHT, content, topology, UDP, QUIC, authenticated routing and IPC suites. |
| Wire characterization baseline | Core `main` 13/13, Android-pinned Core 6/13. The old locally originated fixtures supplied a foreign sender with no request ID. The candidate issues IDs for local senders and explicitly rejects that malformed relay input. |
| New security and resource tests | Sent strict V3 directly and strict V4 over a real TCP relay. Checked hop metadata, author signature format, ciphertext forwarding, replay rejection, forged relay input, reserved queue fairness, count/byte admission and writer budget through I/O. |
| UDP listener baseline and candidate | The same regression times out before receipt of its first packet on the baseline. Both candidate UDP tests pass, covering the first frame, two independent peers, reconnect, unrelated source filtering and malformed input. |
| Android pinned build | Locked Linux Rust bridge tests, 11 passed and 9 ignored. Locked arm64 JNI build with Android NDK 27.3.13750724 succeeded. |
| Android with candidate Core | Locked Linux bridge tests in temporary path-dependency build, 11 passed and 9 ignored. Locked arm64 JNI build succeeded. Manifest changes in the Android branch retain the published Core SHA. |
| Benchmarks | Existing transport, node and simulation benchmarks completed in quick mode. See [measurements and limitations](BENCHMARKS.md). |
| Formatting | Changed Rust files were formatted where applicable. The workspace formatting check reports legacy formatting differences on both the untouched base and candidate. The original workspace-wide strict lint workflow has open legacy issues. |

## F0/F1 follow-up on 24 November 2026

- **QUIC lifecycle.** A strict sender/receiver test reproduced 797/800 and 597/600 unique deliveries. The missing IDs were written, decoded and processed, then rejected by the existing replay window. Reordering originated before writer admission when a concurrent caller yielded after obtaining a sequence number. The same candidate without only the egress gate reproduced the losses, including a background packet. At decode, the lost target probes were already 137–547 sequence positions behind the high-water mark. Locally encrypted terminal recipients now share a fixed, sharded gate from sequence assignment through writer admission. The replay window and all legacy wire formats are unchanged. The earlier 198/200 verification-off run has no stage trace. See [measurements](BENCHMARKS.md).
- **Logging.** Parallel tests exposed a runtime panic when a synchronous component logged after another runtime enabled file logging. A single process-level file writer with 1,024 bounded records (4 KiB per record) replaces one Tokio task per log line. Saturation is counted.
- **Backpressure and shutdown.** Reliable processor ingress waits for capacity, then reports overload and closes the link if admission fails. Oversize sends and closed writers return a downcastable WriterAdmissionError. Cancellation wakes TCP/QUIC readers waiting on a full channel and interrupts active writes. Registered listeners track pending handshake tasks and join or cancel them during stop. Quinn limits connection receive credit and pending incoming bytes. Per-layer bounds and residual risks are recorded in [Architecture](ARCHITECTURE.md#f1-follow-up-limits-and-failure-semantics).
- **Final regression suite.** Cargo release workspace with locked dependencies and the optional lifecycle trace completed with 261 passed, zero failed and one ignored doctest. This included 133 Core unit tests, 14 characterization cases, DHT/content, direct and relay V3/V4, UDP and QUIC, bounded file logging and close with full transport ingress. Ten targeted strict QUIC matrix runs delivered all 25,000 packets, including background. All five targeted repetitions of the original 100 B verify-off benchmark completed without reproducing 198/200.
- **NAT and LAN.** Reviewed upstream [4ed38086](https://github.com/krusalovorg/lp2ln/commit/4ed38086df616e3db346faad20354e32cd5ac149), one commit above the agreed base. Its separate branch passed all three UDP transport/NAT loopback cases. Adopted actual bound port tracking and LAN announcement in the existing runtime flow. The branch's full UDP listener patch overlaps the byte-bounded F1 demultiplexer and would replace its aggregate queue enforcement with item-only queues. Keep the current implementation until the shared UDP/STUN/punch ownership can use the existing global listener budget. This branch test does not validate CGNAT.
- **APK.** Debug arm64 APK built using Rust 1.100.0, NDK 27.3.13750724, JDK 17, Gradle 8.0, AGP 8.0.2 and SDK 34. APK Signature Scheme v2 verified, and the packaged JNI SHA-256 matched the separately built stripped JNI. Project version 1.3.1 (8), min SDK 29, target SDK 34. APK SHA-256 is d44c514d0c6c04d79ce0263b762a68fb39e0d5937d96dacc3106ace7d17e15b5. The Android branch retains the published Core git pin. No target device appeared in adb; no physical install or radio tests were performed.
- **Android regressions.** 7 Kotlin unit tests passed. The host Rust bridge using the local Core passed 11 tests with 9 ignored, including encrypted multi-chunk transfer, remote file acknowledgements, file download through two relays and chat acknowledgements with retry deduplication.
- **F2 review.** Completed [the trust, crypto and compatibility review](F2_SECURITY_REVIEW.md). No F2 security context, handshake, key epochs or new Flow public API is present. Existing legacy direct and relay security tests cover legacy behavior.

### Reproduce the local Android build

1. Copy the Android working tree to an isolated build directory. In that copy replace the Core git dependency with a path to the exact Core checkout under test. Remove the Android root patch that supplies vendored h3-quinn for the published pin, because the local Core already declares its vendored dependency directly. Resolve the isolated manifest against the checked-in lock with Cargo in offline mode, then keep and use the resulting isolated lock with the local source snapshot. The isolated lock used here has SHA-256 08152be6368d8bc44727148bf0edeabca6ba482b19dd11209da9849a584aede3. Keep the original Android manifest and lock with the published pin.
2. Build the isolated Rust bridge for aarch64-linux-android with Cargo 1.100.0 and --locked. Set the linker and C compiler to NDK aarch64-linux-android29-clang and AR to llvm-ar. Strip the resulting JNI file using llvm-strip --strip-unneeded and place it in app/build/generated/lp2ln/jniLibs/arm64-v8a inside the isolated Android project.
3. Run :app:assembleDebug :app:testDebugUnitTest -PrustAbis=arm64-v8a -PskipRustBuild in that copy. Verify with apksigner verify and compare the extracted JNI SHA-256 to the staged JNI. The debug signing key is environment-local, so reproduce the build procedure and source, without expecting the same signed APK hash across different debug keys.

## Remaining release gates

1. Enforce a shared retained-byte budget through transport ingress, active processing and authenticated subscriber handoff. Preserve legacy entry points with an adapter. Test saturation with file, chat, control and topology traffic. Item-only legacy queues and subscriber lag still prevent a general reliable delivery guarantee.
2. Audit chunk pre-auth buffering and stalled/closed sessions throughout the node, including waiting producer-owned bytes, protocol acknowledgements and admission across many simultaneous connections. Verify published and previous V3/V4 clients on real devices, including file/chat, before changing Android's production pin.
3. Once the F0/F1 gates close, implement F2 against the required identity/exporter, Noise and downgrade vectors. F3 and M1 depend on that verified link/endpoint context. Validate shared UDP Punch/STUN ownership with the same memory budget separately.
4. Keep the inherited CI format/lint backlog and device measurements visible. The localhost baseline does not verify WAN handoff or mobile performance.

## Changed files

**Core**

- `.github/workflows/rust.yml`
- `.gitignore`
- `Cargo.lock`
- `Cargo.toml`
- `Dockerfile`
- `crates/lp2ln-core-v2/Cargo.toml`
- `crates/lp2ln-core-v2/benches/network_sim_bench.rs`
- `crates/lp2ln-core-v2/benches/node_bench.rs`
- `crates/lp2ln-core-v2/benches/transport_bench.rs`
- `crates/lp2ln-core-v2/src/packet_processor/chunk_assembler.rs`
- `crates/lp2ln-core-v2/src/packet_processor/processor.rs`
- `crates/lp2ln-core-v2/src/router/dispatch.rs`
- `crates/lp2ln-core-v2/src/router/egress.rs`
- `crates/lp2ln-core-v2/src/router/mod.rs`
- `crates/lp2ln-core-v2/src/router/router.rs`
- `crates/lp2ln-core-v2/src/simulation/network/metrics.rs`
- `crates/lp2ln-core-v2/src/simulation/network/network.rs`
- `crates/lp2ln-core-v2/src/transport/mod.rs`
- `crates/lp2ln-core-v2/src/transport/obfuscation.rs`
- `crates/lp2ln-core-v2/src/transport/quic/session.rs`
- `crates/lp2ln-core-v2/src/transport/tcp/session.rs`
- `crates/lp2ln-core-v2/src/transport/udp/session.rs`
- `crates/lp2ln-core-v2/src/transport/udp/transport.rs`
- `crates/lp2ln-core-v2/src/transport/writer_queue.rs`
- `crates/lp2ln-core-v2/tests/characterization_core.rs`
- `crates/lp2ln-core-v2/tests/dht_smoke.rs`
- `crates/lp2ln-core-v2/tests/relay_wire_compat.rs`
- `crates/lp2ln-core-v2/tests/udp_transport_smoke.rs`
- `docs/realtime/ARCHITECTURE.md`
- `docs/realtime/BENCHMARKS.md`
- `docs/realtime/F2_M1_SPEC.md`
- `docs/realtime/LP2LN_Real_Time_Architecture_Audit.md`
- `docs/realtime/PROGRESS.md`
- `docs/realtime/ROADMAP.md`
- `docs/realtime/SECURITY.md`
- `rust-toolchain.toml`

**Android**

- `app/build.gradle.kts`
- `rust/Cargo.lock`
- `rust/Cargo.toml`
- `rust/rust-toolchain.toml`
- `rust/src/files.rs`

## Follow-up files

Changes in this follow-up are in Core. The Android branch retains the prior F0 tracked changes. The APK test uses the isolated Android workspace.

- `.github/workflows/rust.yml`
- `crates/lp2ln-core-v2/Cargo.toml`
- `crates/lp2ln-core-v2/src/lib.rs`
- `crates/lp2ln-core-v2/src/logger/logger.rs`
- `crates/lp2ln-core-v2/src/node/lan_discovery/mod.rs`
- `crates/lp2ln-core-v2/src/node/runtime/core.rs`
- `crates/lp2ln-core-v2/src/node/runtime/shutdown.rs`
- `crates/lp2ln-core-v2/src/node/runtime/startup/bootstrap.rs`
- `crates/lp2ln-core-v2/src/node/runtime/startup/context.rs`
- `crates/lp2ln-core-v2/src/node/runtime/startup/lan_discovery.rs`
- `crates/lp2ln-core-v2/src/node/runtime/startup/orchestrator.rs`
- `crates/lp2ln-core-v2/src/node/runtime/startup/transports.rs`
- `crates/lp2ln-core-v2/src/packet_processor/processor.rs`
- `crates/lp2ln-core-v2/src/packet_trace.rs`
- `crates/lp2ln-core-v2/src/router/dispatch.rs`
- `crates/lp2ln-core-v2/src/router/egress.rs`
- `crates/lp2ln-core-v2/src/router/router.rs`
- `crates/lp2ln-core-v2/src/transport/mod.rs`
- `crates/lp2ln-core-v2/src/transport/quic/config.rs`
- `crates/lp2ln-core-v2/src/transport/quic/masquerade.rs`
- `crates/lp2ln-core-v2/src/transport/quic/session.rs`
- `crates/lp2ln-core-v2/src/transport/quic/transport.rs`
- `crates/lp2ln-core-v2/src/transport/tcp/codec.rs`
- `crates/lp2ln-core-v2/src/transport/tcp/session.rs`
- `crates/lp2ln-core-v2/src/transport/tcp/transport.rs`
- `crates/lp2ln-core-v2/src/transport/udp/session.rs`
- `crates/lp2ln-core-v2/src/transport/writer_queue.rs`
- `crates/lp2ln-core-v2/tests/quic_packet_lifecycle.rs`
- `docs/realtime/ARCHITECTURE.md`
- `docs/realtime/BENCHMARKS.md`
- `docs/realtime/F2_M1_SPEC.md`
- `docs/realtime/F2_SECURITY_REVIEW.md`
- `docs/realtime/PROGRESS.md`
- `docs/realtime/ROADMAP.md`
- `docs/realtime/SECURITY.md`

## Scoped ingress budget and QUIC replay follow-up

- Native session readers now allocate frame bodies only after a scoped reservation, then move the permit through the weighted Router channel and default processing. The ledger accounts for frame decode, the legacy AEAD overlap, retained chunk fragments and the additional merge allocation. Idle maintenance reaps expired assemblies and consumed legacy ring reservations. Router teardown clears its retained state.
- Legacy Raw and Authenticated broadcast receivers retain their public types. A shared frame across the rings carries one accounting charge. App Plane now consumes the authenticated-envelope stream, reserves each allocated subscriber copy, and uses the same pooled limits for IPC frames. Application-owned values leave Core accounting when handed to the consumer. Legacy byte refusal remains best effort and is observable separately from Tokio broadcast lag and explicit transport failure.
- Replaced recipient hash stripes with keyed, bounded writer gates. A blocked writer for one recipient cannot hold the same async gate as another. In the reconstructed prior candidate, a single-sender strict 8 KiB benchmark lost 1 of 200 frames with one replay rejection and no subscriber or queue drops. The candidate runs same-link authentication and replay checks in receive order, releasing the order guard before application processing or forwarding. Two independent QUIC links still share the legacy author's replay window.
- New exercised cases include an incomplete QUIC body with observable allocation reservation and shutdown release, independent recipients, eligibility of queued work from different sessions, old-path arrival beyond the replay window, unseen in-window reorder, and shared-ring lifetime. The existing sender restart, relay verification and DHT/file/chat regressions are retained.
- Verification reached 268 passed in the full locked release workspace, zero failed and one ignored doctest. Five CPU-pinned lifecycle matrix repeats delivered 12,500/12,500 including background. Three matched runs per benchmark variant are recorded in [BENCHMARKS](BENCHMARKS.md#scoped-ingress-budget-and-ordered-authentication-ab). The 8 KiB throughput regression and increased burst queue age remain visible.
- The rebuilt Android Rust bridge passed 11 host tests with 9 ignored (external/network fixtures). The locked aarch64-linux-android JNI build with NDK r27d succeeded. The Android branch and its published Core pin remain at their incoming state. No installation or call on physical Android devices was exercised. The final targeted Link Survival test also passed after preserving the custom incoming channel behavior of the public racer.
- Stage F1 remains open. Missing work includes the shared UDP wire listener and aggregate native/Quinn receive credit, actual authenticated control reserve, and an overload test for reliable end-to-end handoff with mixed control, chat and file traffic. Separate writer admission, subscriber lag and end-to-end acknowledgement. Receiver restart still uses a fresh in-memory legacy replay window. F2 implementation, verified Flow paths, DATAGRAM/Flow API and M2 are gated.

See [architecture and ownership](ARCHITECTURE.md#prior-node-wide-ingress-accounting-checkpoint), [measurements](BENCHMARKS.md) and [F2 security review](F2_SECURITY_REVIEW.md#updated-f1-observations). No production pin or remote published branch was changed.

## Direct Flow preview on 24 November 2026

- **F1, scoped acceptance.** Integrated UDP listener allocations with managed ingress. Added aggregate QUIC native receive credit, bounded pre-auth buffering and verified control capacity. Included overlapping legacy decode, signature and AEAD work. The managed overload test offers file-sized, chat and actual topology-control frames over TCP while the data ledger is full. Receiver refusal is counted, and subsequent sending observes link failure. The scoped ledger and UDP listener charge-lifetime tests pass. Operating-system socket memory, unmanaged transport providers and applications after handoff are separate. Legacy broadcast loss remains observable via lag or the core refusal metric and requires application-level ACK for reliable semantics.
- **Legacy replay and performance.** The eight-ticket per-link authentication pipeline runs signature and AEAD checks concurrently and commits in receive order. Replay remains shared by signed author across links with the existing window. Process restart clears the legacy receiver replay map. This risk remains present on legacy endpoints. It is isolated from Flow by a dedicated authenticated negotiation and fresh independent Noise session keys and IDs.
- **F2.** Added exporter-bound mutual peer authentication and separate certified Noise XX, directional stateless authentication, separate replay lanes for control and datagrams, bounded epochs and live rekey. Reference and negative tests in flow/vectors.rs cover wire and identity cases. The new handshake requires explicit inbound permission and holds separate pre-auth/native capacity until readiness.
- **F3/M1 local preview.** Public direct Flow sends and receives authenticated datagrams on a verified QUIC path. Checked 60/120/300/1000 B duplex at 50 PPS, expiry under overload, concurrent legacy bulk, rotation with stable ID, sustained 500 PPS per direction, and a deterministic loopback UDP loss/jitter/reorder shim. The shaper models packets between two hosts on loopback and does not exercise a carrier or actual Android path. Path changes terminate the preview.
- **Android readiness.** The Android tree includes a local-only realtime-preview JNI feature and opt-in instrumented two-device test. The published Git pin is unchanged. Physically validating the preview and beginning RTC integration remains a device gate. See the Android checked-in device test instructions.


### Verification for this checkpoint

| Check | Result |
|---|---|
| Locked Core release workspace | 281 passed, zero failed, one ignored doctest. Includes the scoped UDP/QUIC/TCP budgets, cancellation, F2 vectors and direct M1 integration. |
| Legacy QUIC matrix | Five isolated repeats observed 12,500/12,500 deliveries including background. Separate two-link test checks replay across routes, including rejection beyond the fixed legacy window. |
| Crypto datapath A/B | Three runs per variant, all strict and all delivery assertions met. 8 KiB goodput 37.56 → 55.81 MiB/s. Mean ingress queue wait 8.24 → 1.12 ms. See [measurements](BENCHMARKS.md#parallel-authentication-with-ordered-replay-commit). |
| Android preview | Host Rust bridge 11 passed, 9 ignored. Seven Kotlin unit tests passed. Locked ARM64 JNI build succeeded. App and instrumentation APKs compiled and verified with apksigner. Seven JNI exports present. |
| Android physical verification | No target devices attached. The device harness is compiled, so it remains to run it on two Android devices. |

The isolated Android manifest lock for the preview is recorded as SHA-256 168224ba9f5f3279548b1db391e2f88d77d5f05447e6d6db32efe889c75ba76a. The APK uses a separate preview application ID so it can be installed alongside the existing app. Core and Android changes are local. Production deployment still requires Android device and lifecycle testing. M2 needs the device harness followed by the separate lp2ln-rtc integration and a physical voice smoke.

## M2 direct voice preview · 24 November 2026

The software preview includes lp2ln-rtc, negotiated Opus, consent and terminal acknowledgment on reliable control, independent captured and received PCM paths, typed Core teardown, acoustic measurement tooling and Android UI/service/diagnostics. Android's isolated rust-preview manifest refers to this local Core checkout. The ordinary Android lock still selects the published Core. A complete arm64 APK can be built from the two sibling worktrees. See the Android repository's docs/M2_ANDROID.md.

Two host JVMs with independent persistent identities ran the JNI path through invite, accept, two-way Opus, rekey, end acknowledgment and teardown. Core/RTC integration transferred and durably verified a 4 MiB file while processing audio. The deterministic QUIC shim includes a 0.5 Mbit/s serialization limit per direction, loss and reordered delay. Tests also cover bounded overload, revoked admission and cancelled control operations. BENCHMARKS.md records measured values and test exceptions.

The physical M2 acceptance gate is OPEN. No ADB device was attached. LAN discovery on real WLANs, capture/playback hardware, speaker routing, screen-off behavior, subjective echo, device memory and p95 acoustic latency require the supplied two-device test. A remote bootstrap update is unnecessary for this LAN test. M3 implementation is deferred until M2 measurements are available. Relay support will require an independent verified hop and opaque forwarding of endpoint Flow records before an RTC application can select a relayed path.
