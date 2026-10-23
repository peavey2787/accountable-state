# Performance report

Measured with `cargo run --release -p gv-proof-queue --example perf_report --locked` on the
development machine (Windows 11, release profile, nothing else running).

| Component | Cost per operation | Rate |
| --- | --- | --- |
| **crypto and codec** | | |
| ML-DSA-65 sign (150 B) | 605.2 µs | 1652 /s |
| ML-DSA-65 verify | 68.1 µs | 14684 /s |
| input batch sign + encode | 777.5 µs | 1286 /s |
| input batch decode + verify | 65.3 µs | 15321 /s |
| **proof queue (worker side)** | | |
| submit, in-memory journal | 14.5 µs | 69185 /s |
| verify one equivocation job | 274.1 µs | 3648 /s |
| submit, durable file journal (fsync) | 499.3 µs | 2003 /s |
| verify + record verdict, file journal | 1189.0 µs | 841 /s |

**Game thread under load.** `submit` latency while four workers verify a backlog:
p50 31.9 µs, p99 481.8 µs, max 656.5 µs, against a 16.6 ms frame at 60 Hz. Proof work does not
reach gameplay latency.

Figures are one machine's; rerun the example to compare. They are not a guarantee on other hardware.
