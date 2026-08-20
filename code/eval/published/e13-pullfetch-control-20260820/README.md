# Pull/fetch cross-run control (2026-08-20)

Three repetitions of one configuration, to settle whether SafeHub's pull and
fetch reproduce. Same split-host setup as the operations sweep: server farm on
crypto-bench-1 (lane 1, safehub :18192, control :18193, shared git-http :18191),
client on crypto-bench-2. Depth 100, 50 KiB delta, 5 reps per cell (gcrypt 3).

| run | safehub pull | safehub fetch |
|---|---|---|
| 1 | 60 ms | 30 ms |
| 2 | 60 ms | 30 ms |
| 3 | 60 ms | 30 ms |

The operations sweep reports 63 ms and 33 ms at the same depth, so the three
runs agree with it and with each other. Two earlier figures disagreed: the
smoke run (200/197 ms) and a single-host control (88/69 ms). Both differ from
this configuration in host layout, and neither reproduces here, so the
fourfold spread was a property of those runs rather than of the operation.
Pull and fetch are therefore reported in the paper rather than withheld.
