# Benchmark (held-out seeds 1-5, synthetic data)


## Easy data  (72,487 events)

| detector | attacks caught | recall | loud recall | low-and-slow recall | alerts | false alarms | precision | F1 |
|---|---|---|---|---|---|---|---|---|
| rules | 75/75 | 100% | 75/75 (100%) | n/a | 81 | 0 | 100% | 1.00 |
| ml | 45/75 | 60% | 45/75 (60%) | n/a | 45 | 0 | 100% | 0.75 |
| hybrid | 75/75 | 100% | 75/75 (100%) | n/a | 81 | 0 | 100% | 1.00 |
| hybrid + allowlist | 75/75 | 100% | 75/75 (100%) | n/a | 81 | 0 | 100% | 1.00 |

## Hard data  (74,366 events)

| detector | attacks caught | recall | loud recall | low-and-slow recall | alerts | false alarms | precision | F1 |
|---|---|---|---|---|---|---|---|---|
| rules | 75/110 | 68% | 75/75 (100%) | 0/35 (0%) | 133 | 46 | 65% | 0.67 |
| ml | 80/110 | 73% | 45/75 (60%) | 35/35 (100%) | 80 | 0 | 100% | 0.84 |
| hybrid | 110/110 | 100% | 75/75 (100%) | 35/35 (100%) | 168 | 46 | 73% | 0.84 |
| hybrid + allowlist | 110/110 | 100% | 75/75 (100%) | 35/35 (100%) | 153 | 31 | 80% | 0.89 |
