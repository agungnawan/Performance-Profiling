# PQC Benchmark Analysis

Analysis and figure-generation scripts for benchmarking post-quantum cryptographic (PQC) algorithms measured with [liboqs](https://github.com/open-quantum-safe/liboqs). The pipeline turns raw per-run timing data for key encapsulation mechanisms (KEMs) and digital signatures into summary tables, statistical tests, and publication-ready figures.

## Contents

| File | Purpose |
|---|---|
| `analysis.py` | Cleans raw benchmark CSVs, builds summary tables, and runs statistical tests |
| `figs.py` | Produces the figures (trade-off maps, message-size scaling, KEM time breakdown, framework diagram) |
| `sizes.json` | **You must provide this.** Key sizes and NIST security level per algorithm (format below) |

## What the scripts do

### `analysis.py`

1. Loads `kem_benchmark_results.csv` and `signature_benchmark_results.csv`.
2. Assigns each algorithm to a **family** (ML-KEM, Kyber (R3), HQC, BIKE, Classic McEliece, FrodoKEM, NTRU Prime, ML-DSA, Dilithium (R3), Falcon, SPHINCS+, MAYO, CROSS, UOV), a **NIST security level** and a **tier** (levels 1 and 2 map to tier I, 3 to III, 5 to V), and attaches public/secret key sizes from `sizes.json`.
3. Builds per-algorithm summary tables: median, IQR, P95 and max for each operation and for total time, plus output size (ciphertext or signature) and communication cost (public key + output).
4. Tests KEM total time against message size (Spearman correlation).
5. Estimates signature sign/verify scaling with message size using the Theil-Sen estimator (slope in µs/KB, intercept, Spearman rho, and the message size where the size-dependent cost overtakes the fixed cost).
6. Runs Kruskal-Wallis tests across algorithms within each tier, with epsilon-squared effect size.
7. Compares FIPS-standardised algorithms with their Round-3 counterparts (ML-KEM vs Kyber, ML-DSA vs Dilithium, Falcon vs Falcon-padded) using Mann-Whitney U, Cliff's delta, median ratio, and Holm-adjusted p-values.
8. Reports tail behaviour (max/median ratios), Classic McEliece key-generation variability, and runs exceeding 1 s.

### `figs.py`

| Output | Content |
|---|---|
| `fig1_framework.png` | Research framework diagram |
| `fig2_kem_tradeoff.png` | KEM: public key + ciphertext size vs total time (log-log) |
| `fig3_sig_tradeoff.png` | Signatures: signature size vs total time (log-log) |
| `fig4_msg_scaling.png` | Sign and verify time vs message size, with rolling median |
| `fig5_kem_breakdown.png` | Share of keygen / encaps / decaps in total KEM time (Category I and V) |

Figures are saved at 300 dpi.

## Requirements

- Python 3.9+
- `pandas`, `numpy`, `scipy`, `matplotlib`

```bash
pip install pandas numpy scipy matplotlib
```

## Input data

### `kem_benchmark_results.csv`

`algorithm, keygen_time_ms, encap_time_ms, decap_time_ms, ciphertext_length, shared_secret_length, overhead_bytes, total_time_ms, correctness, type, text_size_kb, text_length_bytes, run_id, timestamp, security_level_bits, security_level`

### `signature_benchmark_results.csv`

`algorithm, text_size_kb, keygen_time_ms, sign_time_ms, verify_time_ms, signature_length, overhead_bytes, total_time_ms, correctness, type, text_length_bytes, run_id, timestamp, security_level_bits, security_level`

### `sizes.json`

A mapping from every algorithm name appearing in the CSVs to its NIST level and key sizes in bytes:

```json
{
  "ML-KEM-512": { "level": 1, "public_key": 800, "secret_key": 1632 },
  "ML-DSA-44":  { "level": 2, "public_key": 1312, "secret_key": 2560 }
}
```

Every algorithm name in the CSVs must have an entry, otherwise `analysis.py` raises a `KeyError`. Allowed `level` values are 1, 2, 3 and 5. Algorithm names must start with one of the prefixes recognised by the `family()` function in `analysis.py`; add new prefixes there if you benchmark other schemes.

## Usage

**Before running, update the hard-coded paths** (see Configuration), then:

```bash
python analysis.py   # writes tables and pickles, prints statistics
python figs.py       # reads those outputs, writes figures
```

Run `analysis.py` first: `figs.py` depends on its output files.

### Outputs of `analysis.py`

| File | Content |
|---|---|
| `kem_clean.pkl`, `sig_clean.pkl` | Raw data with added `nist`, `tier`, `family`, `pk`, `sk` columns |
| `kem_table.csv`, `sig_table.csv` | Per-algorithm summary tables |
| `sig_scaling.csv` | Theil-Sen scaling of sign/verify time vs message size |
| `pairs.csv` | FIPS vs Round-3 comparison with effect sizes and Holm-adjusted p-values |

Statistical test results (Kruskal-Wallis, tail behaviour, etc.) are printed to stdout; redirect to a file to keep them:

```bash
python analysis.py > analysis_log.txt
```

## Configuration

Paths are currently hard-coded and must be edited for your machine:

| Script | Variable / line | Default | Change to |
|---|---|---|---|
| `analysis.py` | `pd.read_csv(...)` (2 lines) | `/mnt/user-data/uploads/*.csv` | Location of your CSVs |
| `analysis.py` | `json.load(open('sizes.json'))` | current directory | Location of `sizes.json` |
| `figs.py` | `pd.read_csv` / `pd.read_pickle` (3 lines) | `/home/claude/work/...` | Directory where `analysis.py` wrote its outputs |
| `figs.py` | `OUT` | `/home/claude/work/` | Directory for the PNG figures |

Simplest approach: put everything in one folder and set all paths to `./`.

## Notes and limitations

- `fig1_framework.png` contains fixed text (29 KEM and 56 signature variants, 1,276 message sizes, liboqs 0.13.0). Edit the `steps` list in `figs.py` if your dataset differs.
- Annotation offsets in the scatter plots (`labels` lists in `figs.py`) and the algorithm lists in Figures 4 and 5 are tuned to the original dataset; adjust them if you use different algorithms.
- `analysis.py` uses `groupby(...).apply(...)`, which may emit a `FutureWarning` on recent pandas versions. It does not affect results.
- Timings depend on hardware, compiler flags, and liboqs build; compare results only across runs on the same platform.

## Citation

If you use this code, please cite the accompanying paper:

```
<Authors>. (<Year>). <Title>. <Journal>. <DOI>
```

## License

Add a license of your choice (e.g. TUJ) as `LICENSE`.
