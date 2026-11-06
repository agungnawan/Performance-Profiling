import pandas as pd, numpy as np, json
from scipy import stats
pd.set_option('display.width', 250); pd.set_option('display.max_rows', 300); pd.set_option('display.max_columns', 40)
SZ = json.load(open('sizes.json'))
k = pd.read_csv('/mnt/user-data/uploads/kem_benchmark_results.csv')
s = pd.read_csv('/mnt/user-data/uploads/signature_benchmark_results.csv')

def family(a):
    for p, f in [('ML-KEM', 'ML-KEM'), ('Kyber', 'Kyber (R3)'), ('HQC', 'HQC'), ('BIKE', 'BIKE'),
                 ('Classic-McEliece', 'Classic McEliece'), ('FrodoKEM', 'FrodoKEM'), ('sntrup', 'NTRU Prime'),
                 ('ML-DSA', 'ML-DSA'), ('Dilithium', 'Dilithium (R3)'), ('Falcon', 'Falcon'),
                 ('SPHINCS+', 'SPHINCS+'), ('MAYO', 'MAYO'), ('cross', 'CROSS'), ('OV-', 'UOV')]:
        if a.startswith(p): return f
for d in (k, s):
    d['nist'] = d.algorithm.map(lambda a: SZ[a]['level'])
    d['tier'] = d.nist.map({1: 'I', 2: 'I', 3: 'III', 5: 'V'})
    d['family'] = d.algorithm.map(family)
    d['pk'] = d.algorithm.map(lambda a: SZ[a]['public_key'])
    d['sk'] = d.algorithm.map(lambda a: SZ[a]['secret_key'])
k.to_pickle('kem_clean.pkl'); s.to_pickle('sig_clean.pkl')

def q(x, p): return np.percentile(x, p)
def table(d, ops, lencol):
    rows = []
    for a, g in d.groupby('algorithm'):
        r = dict(algorithm=a, family=g.family.iat[0], nist=g.nist.iat[0], tier=g.tier.iat[0],
                 pk=g.pk.iat[0], sk=g.sk.iat[0], out=int(g[lencol].median()), out_max=int(g[lencol].max()))
        for o in ops + ['total_time_ms']:
            x = g[o].values
            r[o + '_med'] = np.median(x); r[o + '_iqr'] = q(x, 75) - q(x, 25); r[o + '_p95'] = q(x, 95); r[o + '_max'] = x.max()
        rows.append(r)
    return pd.DataFrame(rows).sort_values(['tier', 'total_time_ms_med'])

kt = table(k, ['keygen_time_ms', 'encap_time_ms', 'decap_time_ms'], 'ciphertext_length')
st_ = table(s, ['keygen_time_ms', 'sign_time_ms', 'verify_time_ms'], 'signature_length')
kt['comm'] = kt.pk + kt.out; st_['comm'] = st_.pk + st_.out
kt.to_csv('kem_table.csv', index=False); st_.to_csv('sig_table.csv', index=False)
print(kt[['algorithm', 'nist', 'pk', 'sk', 'out', 'keygen_time_ms_med', 'encap_time_ms_med', 'decap_time_ms_med', 'total_time_ms_med', 'total_time_ms_iqr', 'total_time_ms_p95', 'total_time_ms_max']].round(4).to_string())
print(st_[['algorithm', 'nist', 'pk', 'sk', 'out', 'keygen_time_ms_med', 'sign_time_ms_med', 'verify_time_ms_med', 'total_time_ms_med', 'total_time_ms_iqr', 'total_time_ms_p95']].round(4).to_string())

# message-size independence of KEM
print('\nKEM Spearman total vs size:')
rk = k.groupby('algorithm').apply(lambda g: stats.spearmanr(g.text_size_kb, g.total_time_ms))
print('range rho', min(r[0] for r in rk), max(r[0] for r in rk))

# Message-size scaling for signatures: Theil-Sen per op
rows = []
for a, g in s.groupby('algorithm'):
    r = dict(algorithm=a, family=g.family.iat[0], tier=g.tier.iat[0])
    for o in ['sign_time_ms', 'verify_time_ms']:
        sl, ic, lo, hi = stats.theilslopes(g[o], g.text_size_kb)
        rho = stats.spearmanr(g.text_size_kb, g[o])[0]
        r[o + '_slope_us_per_kb'] = sl * 1000; r[o + '_icpt_ms'] = ic; r[o + '_rho'] = rho
        r[o + '_lo'] = lo * 1000; r[o + '_hi'] = hi * 1000
        r[o + '_cross_kb'] = ic / sl if sl > 0 else np.nan
    rows.append(r)
sc = pd.DataFrame(rows).sort_values(['family', 'algorithm'])
sc.to_csv('sig_scaling.csv', index=False)
print(sc.round(3).to_string())

# hypothesis tests
print('\n=== Kruskal-Wallis across algorithms within tier ===')
for name, d, col in [('KEM', k, 'total_time_ms'), ('SIG sign', s, 'sign_time_ms'), ('SIG verify', s, 'verify_time_ms')]:
    for t, g in d.groupby('tier'):
        H, p = stats.kruskal(*[x[col].values for _, x in g.groupby('algorithm')])
        n = len(g); kk = g.algorithm.nunique(); eps2 = (H - kk + 1) / (n - kk)
        print(name, t, 'k=', kk, 'H=%.1f p=%.2e eps2=%.3f' % (H, p, eps2))

def cliff(a, b):
    u = stats.mannwhitneyu(a, b).statistic
    return 2 * u / (len(a) * len(b)) - 1
print('\n=== FIPS vs Round-3 pairs (Mann-Whitney, Cliff delta, median ratio) ===')
pairs = [('ML-KEM-512', 'Kyber512', k), ('ML-KEM-768', 'Kyber768', k), ('ML-KEM-1024', 'Kyber1024', k),
         ('ML-DSA-44', 'Dilithium2', s), ('ML-DSA-65', 'Dilithium3', s), ('ML-DSA-87', 'Dilithium5', s),
         ('Falcon-512', 'Falcon-padded-512', s), ('Falcon-1024', 'Falcon-padded-1024', s)]
res = []
for a, b, d in pairs:
    ops = ['keygen_time_ms', 'encap_time_ms', 'decap_time_ms'] if d is k else ['keygen_time_ms', 'sign_time_ms', 'verify_time_ms']
    for o in ops + ['total_time_ms']:
        x = d[d.algorithm == a][o].values; y = d[d.algorithm == b][o].values
        p = stats.mannwhitneyu(x, y).pvalue
        res.append(dict(a=a, b=b, op=o, med_a=np.median(x), med_b=np.median(y), ratio=np.median(x) / np.median(y), p=p, delta=cliff(x, y)))
pr = pd.DataFrame(res); pr['p_holm'] = np.minimum(1, pr.p.rank().map(lambda r: 0) + pr.p)  # placeholder
m = len(pr); order = pr.p.argsort().values; adj = np.empty(m); run = 0
for i, idx in enumerate(order):
    run = max(run, min(1, (m - i) * pr.p.iat[idx])); adj[idx] = run
pr['p_holm'] = adj
pr.to_csv('pairs.csv', index=False); print(pr.round(4).to_string())

# outliers and warm-up
print('\n=== tail behaviour: max/median ratio top ===')
for name, d in [('KEM', k), ('SIG', s)]:
    g = d.groupby('algorithm').total_time_ms
    rr = (g.max() / g.median()).sort_values(ascending=False).head(8); print(name, rr.round(1).to_dict())
mc = k[k.algorithm.str.startswith('Classic')]
print('McEliece keygen CV%', (mc.groupby('algorithm').keygen_time_ms.std() / mc.groupby('algorithm').keygen_time_ms.mean() * 100).round(1).to_dict())
print('McEliece keygen IQR/med', (mc.groupby('algorithm').keygen_time_ms.apply(lambda x: (q(x, 75) - q(x, 25)) / np.median(x))).round(2).to_dict())
print('runs > 1s', (k.total_time_ms > 1000).sum(), k[k.total_time_ms > 1000][['algorithm', 'run_id', 'total_time_ms']].to_string())
# share of keygen in total for McEliece
print('keygen share', (mc.groupby('algorithm').keygen_time_ms.median() / mc.groupby('algorithm').total_time_ms.median()).round(3).to_dict())
