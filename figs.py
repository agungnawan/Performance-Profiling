import pandas as pd, numpy as np, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from matplotlib.lines import Line2D

plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 8, 'axes.edgecolor': '#52514e', 'axes.linewidth': 0.6,
                     'axes.labelcolor': '#0b0b0b', 'xtick.color': '#52514e', 'ytick.color': '#52514e',
                     'axes.spines.top': False, 'axes.spines.right': False, 'savefig.dpi': 300})
PAL = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948']
MK = {'I': 'o', 'III': 's', 'V': '^'}
GRID = dict(color='#e4e3df', lw=0.5)
kt = pd.read_csv('/home/claude/work/kem_table.csv'); st = pd.read_csv('/home/claude/work/sig_table.csv')
s = pd.read_pickle('/home/claude/work/sig_clean.pkl')
OUT = '/home/claude/work/'

def tierleg(ax, loc):
    h = [Line2D([], [], marker=MK[t], ls='', color='#52514e', mfc='none', ms=6, label=f'Category {t}') for t in MK]
    return ax.legend(handles=h, loc=loc, frameon=False, fontsize=7, title='NIST security', title_fontsize=7)

def scatter(df, fams, xcol, ycol, xl, yl, fn, labels):
    fig, ax = plt.subplots(figsize=(6.3, 4.2))
    for i, f in enumerate(fams):
        d = df[df.family == f]
        for t, g in d.groupby('tier'):
            ax.scatter(g[xcol], g[ycol], s=34, marker=MK[t], color=PAL[i], edgecolor='white', lw=0.8, zorder=3)
    ax.set_xscale('log'); ax.set_yscale('log'); ax.grid(True, which='major', **GRID); ax.set_axisbelow(True)
    ax.set_xlabel(xl); ax.set_ylabel(yl)
    h = [Line2D([], [], marker='o', ls='', color=PAL[i], ms=6, label=f) for i, f in enumerate(fams)]
    l1 = ax.legend(handles=h, loc='upper left', frameon=False, fontsize=7, title='Family', title_fontsize=7)
    ax.add_artist(l1); tierleg(ax, 'lower right')
    for a, dx, dy in labels:
        r = df[df.algorithm == a].iloc[0]
        ax.annotate(a, (r[xcol], r[ycol]), xytext=(dx, dy), textcoords='offset points', fontsize=6.5, color='#52514e',
                    arrowprops=dict(arrowstyle='-', color='#a8a7a2', lw=0.5))
    fig.tight_layout(); fig.savefig(OUT + fn); plt.close(fig)

kf = ['ML-KEM', 'Kyber (R3)', 'NTRU Prime', 'HQC', 'BIKE', 'FrodoKEM', 'Classic McEliece']
scatter(kt, kf, 'comm', 'total_time_ms_med', 'Public key + ciphertext (bytes, log scale)',
        'Median keygen + encaps + decaps time (ms, log scale)', 'fig2_kem_tradeoff.png',
        [('ML-KEM-768', 18, -14), ('sntrup761', -10, 14), ('HQC-128', -40, 14), ('BIKE-L1', -45, 8),
         ('FrodoKEM-640-AES', 8, -14), ('Classic-McEliece-348864f', -100, 10), ('Classic-McEliece-8192128', -110, 6)])

sf = ['ML-DSA', 'Dilithium (R3)', 'Falcon', 'SPHINCS+', 'MAYO', 'CROSS', 'UOV']
scatter(st, sf, 'out', 'total_time_ms_med', 'Signature size (bytes, log scale)',
        'Median keygen + sign + verify time (ms, log scale)', 'fig3_sig_tradeoff.png',
        [('MAYO-2', 6, 14), ('ML-DSA-44', 10, -16), ('Falcon-512', 10, 10), ('OV-Is', 6, 16),
         ('SPHINCS+-SHA2-128s-simple', -125, 6), ('SPHINCS+-SHA2-128f-simple', -60, 14), ('cross-rsdpg-128-fast', -40, -18),
         ('OV-V', 8, 6)])

# Fig 4: verification time vs message size
sel = [('ML-DSA-44', PAL[0]), ('Falcon-512', PAL[2]), ('MAYO-2', PAL[4]), ('OV-Ip', PAL[6]),
       ('cross-rsdpg-128-fast', PAL[5]), ('SPHINCS+-SHA2-128s-simple', PAL[3])]
fig, axs = plt.subplots(1, 2, figsize=(6.3, 3.0), sharex=True)
for a, c in sel:
    g = s[s.algorithm == a].sort_values('text_size_kb')
    for ax, col in zip(axs, ['sign_time_ms', 'verify_time_ms']):
        if a.startswith('SPHINCS') and col == 'sign_time_ms': continue
        roll = g[col].rolling(41, center=True, min_periods=10).median()
        ax.scatter(g.text_size_kb, g[col], s=1.2, color=c, alpha=0.18, lw=0, rasterized=True)
        ax.plot(g.text_size_kb, roll, color=c, lw=2, label=a)
for ax, t in zip(axs, ['(a) Signing', '(b) Verification']):
    ax.set_title(t, fontsize=8, loc='left'); ax.set_xlabel('Message size (KB)'); ax.grid(True, **GRID); ax.set_axisbelow(True)
axs[0].set_ylabel('Time (ms)'); axs[0].set_ylim(0, 1.2); axs[1].set_ylim(0, 1.2)
h, l = axs[1].get_legend_handles_labels()
fig.legend(h, l, loc='lower center', ncol=3, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.01))
fig.tight_layout(rect=(0, 0.12, 1, 1)); fig.savefig(OUT + 'fig4_msg_scaling.png'); plt.close(fig)

# Fig 5: KEM operation breakdown, Category I and V
sub = kt[kt.algorithm.isin(['ML-KEM-512', 'sntrup761', 'HQC-128', 'FrodoKEM-640-AES', 'BIKE-L1', 'Classic-McEliece-348864f',
                            'ML-KEM-1024', 'HQC-256', 'FrodoKEM-1344-AES', 'BIKE-L5', 'Classic-McEliece-6688128f'])].copy()
sub = sub.sort_values(['tier', 'total_time_ms_med'], ascending=[False, True])
fig, ax = plt.subplots(figsize=(6.3, 3.4))
y = np.arange(len(sub)); left = np.zeros(len(sub))
for col, c, lab in [('keygen_time_ms_med', PAL[0], 'Key generation'), ('encap_time_ms_med', PAL[1], 'Encapsulation'), ('decap_time_ms_med', PAL[2], 'Decapsulation')]:
    v = sub[col].values
    ax.barh(y, v / sub.total_time_ms_med.values * 100, left=left, color=c, edgecolor='white', lw=1, height=0.7, label=lab)
    left += v / sub.total_time_ms_med.values * 100
ax.set_yticks(y); ax.set_yticklabels([f"{a}  ({t:.3g} ms)" for a, t in zip(sub.algorithm, sub.total_time_ms_med)], fontsize=7)
ax.set_xlabel('Share of median total KEM time (%)'); ax.set_xlim(0, 100); ax.invert_yaxis()
ax.axhline(5.5, color='#a8a7a2', lw=0.6, ls='--')
ax.text(101, 2.5, 'Cat. V', fontsize=7, color='#52514e', va='center'); ax.text(101, 8.5, 'Cat. I', fontsize=7, color='#52514e', va='center')
ax.legend(loc='lower center', ncol=3, frameon=False, fontsize=7, bbox_to_anchor=(0.4, -0.3))
fig.tight_layout(); fig.savefig(OUT + 'fig5_kem_breakdown.png'); plt.close(fig)

# Fig 1: research framework
fig, ax = plt.subplots(figsize=(6.3, 2.2)); ax.axis('off'); ax.set_xlim(0, 100); ax.set_ylim(0, 30)
steps = [('Algorithm set', '29 KEM and\n56 signature\nvariants\n(liboqs 0.13.0)'),
         ('Workload', '1,276 message\nsizes, 0.5–128\nKB in 0.1 KB\nsteps'),
         ('Measurement', 'keygen, encaps/\ndecaps or sign/\nverify time;\ncorrectness'),
         ('Preprocessing', 'NIST category\nrelabelling;\nkey and artefact\nsizes'),
         ('Analysis', 'median, IQR,\nP95; Kruskal–\nWallis; Theil–\nSen; Cliff δ'),
         ('Synthesis', 'trade-off maps\nand use-case\nrecommend-\nations')]
w = 15.2
for i, (t, d) in enumerate(steps):
    x = 0.5 + i * 16.6
    ax.add_patch(FancyBboxPatch((x, 4), w, 22, boxstyle='round,pad=0.4,rounding_size=1.5', fc='#eef4fc', ec=PAL[0], lw=0.8))
    ax.text(x + w / 2, 22, t, ha='center', va='center', fontsize=7, weight='bold', color='#0b0b0b')
    ax.text(x + w / 2, 11.5, d, ha='center', va='center', fontsize=6.3, color='#52514e', linespacing=1.3)
    if i < len(steps) - 1:
        ax.annotate('', xy=(x + w + 1.6, 15), xytext=(x + w + 0.3, 15), arrowprops=dict(arrowstyle='-|>', color='#52514e', lw=0.8))
fig.tight_layout(); fig.savefig(OUT + 'fig1_framework.png'); plt.close(fig)
print('ok')
