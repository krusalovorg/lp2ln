# F0/F1 Benchmarks

The [original audit](LP2LN_Real_Time_Architecture_Audit.md#10-план-тестирования-и-baseline) contains the baseline measured on Core `65925aaf`. Test host was Linux x86-64 on AMD EPYC 9V74, Rust 1.100.0 and Quinn 0.11.11. Results below are release Criterion quick estimates and same-host socket probes. They characterize local behavior. WAN/Mobile latency, radio energy and CPU on Android require device tests.

## Reproduce

```sh
cargo bench --locked -p lp2ln-core-v2 --bench transport_bench -- --quick
LP2LN_BENCH_UDP=1 LP2LN_BENCH_CPU=1 cargo bench --locked -p lp2ln-core-v2 --bench node_bench -- --quick
BENCH_PROFILE=quick cargo bench --locked -p lp2ln-core-v2 --bench network_sim_bench -- --quick
```

- `enqueue_throughput` measures bytes submitted successfully to the session writer. It preserves the previous transport metric under a more specific name.
- `latency` measures a 64-byte echo with a matching request ID and a deadline.
- TCP/QUIC NodeRuntime throughput requires every expected ID and the correct matching decrypted payload. Lost, stale, unrelated, duplicate or broadcast-lagged packets do not satisfy the count. One deadline covers send and receive. The UDP probe uses a 100 ms observation window and reports goodput from unique receives. It uses two preconnected loopback sockets. Listener demultiplexing has its own integration tests.
- `LP2LN_BENCH_CPU=1` runs a verified QUIC batch CPU profile and a separate paced 50 PPS observation. Report nearest-rank p50/p95/p99 of same-host send-to-subscriber latency and smoothed absolute difference between consecutive valid transit times. In-progress loss and historical subscriber lag are independently observable.
- The simulated batch validates only the IDs allocated to that batch and requires full delivery for the declared throughput. Sender work and receiver collection share the same wall-time budget.
- Processes sampled under other host work may produce noisy CPU or throughput estimates. The TCP A/B below controls the socket flag on both endpoints. Receiver queue wait excludes socket queues, decryption time and application jitter buffering.

## Transport microbench

| Measurement | Before | F1, before vectored framing | F1, after vectored framing |
|---|---:|---:|---:|
| TCP echo RTT, 64 B | 88.032 ms | 55.372 µs | 62.096 µs |
| TCP enqueue throughput, 100 B | 40.57 MiB/s | 6.30 MiB/s | 63.36 MiB/s |
| TCP enqueue throughput, 8 KiB | 454.17 MiB/s | 413.33 MiB/s | 510.86 MiB/s |
| UDP echo RTT, 64 B | 60.31 µs | 36.17 µs | same UDP code |
| QUIC stream echo RTT, 64 B | 58.94 µs | 71.59 µs | same QUIC code |

The TCP experiment used two loopback sockets, a 4-byte length followed by a 64-byte payload, and two `sendall` calls per direction. With 40 warm observations per setting, the median was **87,991.7 µs** with Nagle enabled and **47.7 µs** with `TCP_NODELAY` on both endpoints. Holding the split framing constant isolates the socket option. The delay matches interaction between tiny writes, Nagle and delayed ACK. TCP packet traces were outside this run. Enabling `TCP_NODELAY` alone made separate header/payload submissions expensive for bursts. Vectored writes recovered throughput without allocating a contiguous buffer or changing the framing. The TCP regression covers partial writes within the header and within the payload. [Linux TCP socket options](https://man7.org/linux/man-pages/man7/tcp.7.html) · [RFC 1122](https://www.rfc-editor.org/rfc/rfc1122.html#page-95)

## NodeRuntime and simulation

| Check | Baseline | F1 observation |
|---|---:|---:|
| NodeRuntime TCP verify-on, 8 KiB | 56.83 MiB/s | 57.64 MiB/s |
| NodeRuntime TCP verify-on, 64 KiB | 197.89 MiB/s | 166.03 MiB/s |
| NodeRuntime QUIC verify-on, 8 KiB | 63.61 MiB/s | 63.58 MiB/s |
| NodeRuntime QUIC verify-on, 64 KiB | 183.56 MiB/s | 173.39 MiB/s |
| Simulator batch, 100 nodes, 10 × 8 KiB | 317.88 ms, 10/10 | 120.10 ms, 10/10 |
| Live loopback TCP chain, five nodes | 268.43 µs | 248.14 µs |
| Live loopback TCP chain, ten nodes | 447.10 µs | 337.30 µs |

The NodeRuntime numbers are from the final complete quick run. The simulation and chain results are from the first complete F1 run, before the TCP vectored follow-up and shared broadcast allocation. The tightened receive matcher changes the measurement method. The results show local observations and do not isolate the effect of any single change. Criterion quick samples and topology randomness further limit comparisons.

- Verified QUIC, 100 B, paced 50 PPS. The first run observed 250/250 with p50 584 µs, p95 899 µs, p99 1,429 µs, smoothed jitter 154 µs and 5,018 B/s payload goodput. Receiver queue wait across the burst and paced runs averaged 137 µs and peaked at 4,597 µs. Process peak was 208.1% with 100% representing one logical CPU. The final run observed 250/250, p50 639 µs, p95 1,713 µs, p99 10,113 µs and jitter 167 µs. Queue wait averaged 166 µs and peaked at 9,359 µs across both loads. Process peak was 212.6%. A run during overlapping builds observed p99 17,052 µs. These runs describe local end-to-end harness latency.
- UDP, verified, 8 KiB. An initial run observed 200/200 and 61.2 MB/s. A separate run during other build activity observed 128/200 within 100 ms. Its goodput was 10.0 MB/s. The final full probe observed 136/200. An isolated run with stage counters observed 200/200. A single-logical-CPU run reproduced 113/200 with verify off and 84/200 with verify on. Both receiver counts matched decoded ingress and there were no processor-queue or replay rejections. Linux `Udp:RcvbufErrors` rose by 203, exactly the combined misses in those two batches. This establishes receive-buffer overflow in that controlled burst. Socket buffer and pacing tuning should be tested with actual UDP payload sizes and production traffic. All runs terminated.
- A separate isolated QUIC 100 B verify-off quick run failed an assertion at 198 unique deliveries from 200 sends. With replay/late counters and richer failure output enabled, a focused follow-up completed 20 measured samples without reproducing the batch failure. The historical batch has no per-ID trace. The follow-up below reproduces and isolates replay rejection under comparable load in strict mode.

Further profiling should time postcard decode/encode, stream framing and queue allocation separately from signature work. At the current workload, the large QUIC stream number warrants a matched methodology rerun. The results do not isolate the impact of sender budgets, target-side validation or the background scheduler.

## QUIC lifecycle follow-up

Reproduce the strict lifecycle matrix using Cargo 1.100.0 and the locked dependencies:

~~~bash
cargo test --locked --release -p lp2ln-core-v2 --features packet-trace --test quic_packet_lifecycle -- --nocapture
cargo bench --locked -p lp2ln-core-v2 --bench node_bench -- 'node_throughput_prod/quic' --quick
~~~

Both endpoints run on Linux loopback with verification and secure envelopes enabled. Each run validates unique request IDs, protocol, payload and subscriber lag. The before column disables only the sequence-to-writer gate in a temporary copy. It retains wire format, authentication, queue handling and deadlines. The after column combines ten runs. The milliseconds describe completion of the full case and are neither packet latency percentiles nor WAN measurements.

| Payload | Writer futures / processor workers | Background | Before | After, 10/10 runs | Final batch median and range |
|---|---:|---|---:|---:|---:|
| 100 B | 1 / 256 | none | 200/200 | 2,000/2,000 | 17 ms (14–31 ms) |
| 1,200 B | 4 / 16 | none | 797/800 | 8,000/8,000 | 81.5 ms (73–167 ms) |
| 64 KiB | 4 / 64 | none | 200/200 | 2,000/2,000 | 89.5 ms (75–203 ms) |
| 8 KiB | 4 / 256 | 700 packets alternating 100 B and 64 KiB | 597/600 target and 699/700 background | 6,000/6,000 target and 7,000/7,000 background | 251 ms (229–321 ms) |

Before the gate, every missing ID reached writer admission, stream write, decode, Router ingress and processing, then failed replay. Cases showed zero frame decoder errors, zero processor refusal and zero subscriber lag. The six target frames were already 137–547 sequence positions behind the highest decoded when reaching QUIC decode. The missing background frame was 126 behind at decode and rejected later by the 128-position receiver window. Tokio cooperative scheduling can yield between sequence assignment and writer admission; a different sender future can append much newer packets in that interval. Routing all concurrently prepared local envelopes for the same recipient through one gate removes that reorder source. Release code does not install a packet probe. No receiver replay rule changed.

The exact historical 198/200 count did not recur in the ten corrected runs. Historical verification-off mode and this strict test are separate measurements.

### Strict QUIC goodput

Criterion quick, subscriber-confirmed payload on loopback. The follow-up numbers come from the production build without the packet-trace feature. All measured reliable batches satisfied the exact delivery assertion.

| Payload | Original pin baseline | Previous isolated F1 | Follow-up quick estimate |
|---|---:|---:|---:|
| 8 KiB | 63.61 MiB/s | 63.58 MiB/s | 58.49 MiB/s (57.81–58.66) |
| 64 KiB | 183.56 MiB/s | 173.39 MiB/s | 149.78 MiB/s (149.47–151.04) |

The quick observations are lower than the prior isolated run. The two runs do not isolate the cost of the gate or of the transport/admission changes. A full fixed-CPU repeated A/B with separate send admission, wire decode, AEAD and queue wait timers is required for a causal performance conclusion. No cipher or replay checks were disabled in these cases.

Five focused quick repeats of the original 100 B verification-off benchmark all satisfied the reliable delivery assertion. The separate strict paced probe delivered 250/250 at 50 PPS and 5,018 B/s, with p50/p95/p99 of 493/1,873/6,518 µs and jitter of 113 µs. Its preceding strict 8 KiB burst and paced probe together recorded 63,652 decoded and authenticated deliveries, zero replay or admission drops, mean/max queue age of 155/6,665 µs and process peak of 204.8%, with one logical CPU representing 100%. The previous F1 paced run reported 639/1,713/10,113 µs and 167 µs jitter. These are individual host observations with no WAN, mobile power or retransmission-tail conclusions.

## Scoped ingress budget and ordered authentication A/B

Same Linux host and pinned Rust/Cargo lock, release build, four logical CPUs (1–4), strict packet verification on every variant. Three fresh executable runs each, with the second round in reverse order. A reconstructs the previous F1 candidate with the egress gate intact. B includes scoped budget and exact-recipient egress ordering, before the per-link receive order. C includes per-link receive order. The common harness counts successful alloc/alloc_zeroed/realloc calls process-wide during the four-second burst, including runtime tasks. Peak RSS is sampled every 100 ms. Criterion quick estimates are separate from the allocation probe.

~~~bash
cargo bench --locked -p lp2ln-core-v2 --bench node_bench --no-run
LP2LN_BENCH_CPU=1 LP2LN_BENCH_ALLOCATIONS=1 LP2LN_BENCH_PROBE_SECS=4 \
  taskset -c 1-4 <node_bench_binary> 'node_throughput_prod/quic' --bench --quick --noplot
~~~

| Median across three runs | A · previous F1 | B · budget | C · budget and link order |
|---|---:|---:|---:|
| 8 KiB subscriber-confirmed goodput · Criterion | 60.55 MiB/s | 57.67 MiB/s | 36.14 MiB/s |
| 64 KiB subscriber-confirmed goodput · Criterion | 145.72 MiB/s | 147.61 MiB/s | 141.03 MiB/s |
| 8 KiB measured burst · PPS | 7,530 | 7,403 | 4,743 |
| 8 KiB measured burst · delivered goodput | 58.83 MiB/s | 57.84 MiB/s | 37.05 MiB/s |
| 100 B at 50 PPS · p50 / p95 / p99 | 492 / 838 / 4,535 µs | 507 / 779 / 3,391 µs | 563 / 941 / 1,861 µs |
| 100 B at 50 PPS · jitter | 512 µs | 151 µs | 136 µs |
| Burst and paced · mean / max queue wait | 642 / 8,329 µs | 648 / 6,940 µs | 8,426 / 44,617 µs |
| Peak process CPU · 100% is one logical CPU | 165.9% | 160.3% | 106.8% |
| Peak process RSS | 35.86 MiB | 36.24 MiB | 37.30 MiB |
| Allocation/reallocation calls per 8 KiB delivery | 83.96 | 86.95 | 89.36 |
| Bytes requested from allocator per 8 KiB delivery | 99,808 | 100,055 | 100,466 |
| Peak scoped node usage | unavailable | 1.89 MiB | 2.71 MiB |
| Scoped ledger lock contentions during both probes | unavailable | 860 | 444 |
| Egress ordering waits in the single-writer workload | unavailable | 0 | 0 |

All nine matched runs met the exact delivered count assertions. Every paced probe delivered 250/250 with no subscriber lag. Candidates B/C had zero byte-admission refusals in those loads. In a separate exploratory attempt before the matched set, A failed the reliable assertion at 199/200 with one replay rejection, zero queue drops and zero subscriber lag. That attempt contributes no goodput value to this table. It establishes a residual same-link regression with the old gate present. The final candidate delivered 12,500/12,500 in five extra strict QUIC matrix runs, including competing 100 B and 64 KiB traffic. The multi-link test accepts unseen in-window reordering and rejects an old packet outside the existing window.

Most of the observed 8 KiB throughput reduction appears in C, where each input link serializes authentication and the replay check. The queue grows under the same burst while measured CPU falls toward one busy core. The 64 KiB results are close relative to quick-run dispersion. B adds allocations and contention with a smaller observed 8 KiB change. The variants include small accompanying lifecycle and accounting changes, so the numbers are not a cycle-by-cycle attribution. Paced p99 varied substantially across the three samples and covers a different workload from burst queue wait. The next performance step is to parallelize verification while preserving ordered replay commits. None of these runs establish WAN, radio, multipath or physical Android behavior.

## Parallel authentication with ordered replay commit

Identical current source and lock for both variants except DefaultPacketProcessor::parallel_authentication returned false for the serial reference. The serial path has one in-flight job per input link and the candidate up to eight. Both variants used four pinned logical CPUs, strict signatures/AEAD/replay, the same burst and paced tests, and three repeated release runs with reversed order in the second round. Allocator calls were counted during the four-second burst. Criterion quick results provide separate delivered-goodput estimates.

| Median across three runs | Serial | Parallel with ordered commit |
|---|---:|---:|
| 8 KiB subscriber-confirmed goodput · Criterion | 37.56 MiB/s | 55.81 MiB/s |
| 64 KiB subscriber-confirmed goodput · Criterion | 149.12 MiB/s | 137.06 MiB/s |
| 8 KiB burst · PPS | 4,198 | 7,330 |
| 8 KiB burst · delivered goodput | 32.80 MiB/s | 57.26 MiB/s |
| 100 B at 50 PPS · p50 / p95 / p99 | 577 / 3,109 / 8,826 µs | 591 / 5,289 / 5,842 µs |
| 100 B at 50 PPS · jitter | 265 µs | 213 µs |
| Burst and paced · mean / max queue wait | 8,241 / 98,150 µs | 1,123 / 20,316 µs |
| Peak process CPU · 100% is one logical CPU | 105.0% | 160.9% |
| Peak process RSS | 38.10 MiB | 37.67 MiB |
| Allocation/reallocation calls per 8 KiB delivery | 89.32 | 88.30 |
| Ingress accounting contention counts | 379 | 783 |

All six runs met exact delivery assertions. Both variants reported zero replay rejection and reliable admission refusal in these loads. The improvement at 8 KiB is consistent with the previously serialized receive checks limiting CPU utilization. At 64 KiB the quick-run spreads overlap (91.15–166.14 and 63.46–175.72 MiB/s). There is no supported conclusion about a stable change at that size. The paced tail results also varied across repeated runs. This test does not isolate a lock from the compute it protects.

## Direct Flow preview probes

The integration entry point is cargo test --locked --release -p lp2ln-core-v2 --test flow_realtime -- --nocapture. The unchanged legacy benchmark above characterizes the reliable path, while this harness validates the new Flow semantics.

- Direct QUIC loopback at 50 PPS per direction, 50/50 for each side at each of 60, 120, 300 and 1,000 B. The 60 B case overlaps 240 signed 64 KiB legacy bulk frames and observes all of them at the receiver on the same QUIC listener using the legacy ALPN.
- Direct higher-rate profile after live key rotation, 1,000 B and 500 PPS per direction, 400/400 deliveries on each side in the initial run. This exercises packet rates above audio without requiring a VPN or codec dependency.
- The UDP shaper applies 5–21 ms packet delay variation, drops every thirteenth observed packet after setup, and forwards some out of input order. In the first shaped run, 73/75 and 69/75 application datagrams were observed. The shaper recorded 19 dropped and 65 transport packets delivered out of order. Transport packet counts include QUIC ACKs and are separate from application delivery. Authenticated application delivery recorded zero invalid authentication or replay faults.
- The overload probe deliberately stops polling the consumer, observes queue pressure and expiry, verifies idle release of the ingress charge, then receives fresh data. It also checks MTU, local expired offers, close and native credit release.
- The tests do not model mobile radio, packet fragmentation across a real WAN, interface transitions or two physical devices. Inspect the protocol counters and device-test outputs separately.

## M2 direct audio and M1 endurance, 24 November 2026

Two separate 1,200 s release-mode loopback runs targeted simultaneous independent 50 and 500 PPS Flows in both directions, 120 B payload, 180 ms deadline. The initiator of each Flow rotated keys first at 3 s and then every 60 s. Both nodes ran in one Linux process with a shared monotonic clock. Other builds/tests ran on the host concurrently. Tokio skipped missed generation ticks. Compare remote handoffs to actual peer offers separately from the target rate. The second run below includes per-Flow queue times and process resource sampling. The first run delivered 59,637/59,643 frames and 560,686/561,334 frames (two directions), with zero invalid/replay events.

| Target PPS | Receiver | Delivered frames | Actual RX PPS | Payload kbit/s | Handoff latency p50/p95/p99 ms | Final jitter EWMA ms | Queue mean/max ms | Expired/invalid/replay |
|---:|---|---:|---:|---:|---|---:|---|---|
| 50 | initiator | 59667 | 49.72 | 47.73 | 0.2 / 1.4 / 7.2 | 0.157 | 0.088 / 55.10 | 0 / 0 / 0 |
| 50 | responder | 59671 | 49.73 | 47.74 | 0.2 / 1.4 / 7.1 | 0.107 | 0.088 / 55.05 | 0 / 0 / 0 |
| 500 | initiator | 565851 | 471.54 | 452.68 | 0.2 / 0.7 / 4.5 | 0.265 | 0.054 / 59.62 | 1 / 0 / 0 |
| 500 | responder | 566671 | 472.23 | 453.34 | 0.2 / 0.8 / 5.0 | 0.193 | 0.058 / 55.49 | 0 / 0 / 0 |

Latency uses upper bounds of 100 µs histogram bins. Jitter measures absolute successive transit-time variation. Queue time covers authenticated ingress insertion to application handoff. Over 1185 sampled seconds, process CPU averaged 19.6% of one core. RSS sampled every 15 s was initially 12388 KiB, peaked at 12708 KiB and ended at 8004 KiB. Samples show no sustained RSS growth in this run. Allocator lifetime and hardware audio resources require separate device measurements.

The loss/jitter/reorder UDP shim capped each direction at 0.5 Mbit/s with bounded buffering and deterministic periodic drops. The short test observed 68/68 packets out of 75 offered per direction. The durable-file integration played 143/148 out of 150 source slots per direction, including receiver prefill, while rekeying and transferring a SHA-256-verified 4 MiB file over the legacy block service. Two separate JVMs observed 140 and 145 non-silent PCM frames using the Android JNI entry points and host libopus 1.6.1. An acoustic analyzer fixture recovered 21 of 21 markers at a known 140 ms offset. No device acoustic latency was measured.

Reproduce the long run with cargo test --locked --release -p lp2ln-core-v2 --test flow_realtime simultaneous_flow_endurance -- --ignored --nocapture. Use cargo test --locked --release -p lp2ln-rtc --test voice_flow -- --nocapture for file competition and decoded audio. LP2LN_SOAK_SECONDS can shorten the endurance test for development.

Final serialized Core/RTC suites: 226 passed, one long test invoked separately, one ignored doctest. A parallel suite run stalled in two_node_announce_and_find and was interrupted. The DHT binary subsequently passed four independent default-concurrency runs (6/6 each). Root cause remains open. Android Rust host regressions passed 11, with 9 explicit skips. Kotlin unit tests passed 7. The arm64 build and APK signature checks passed. Device-only gates remain open.
