"""deep_analysis.py - Phan tich sau ve feature LLR va encoding"""
import pandas as pd
import numpy as np
import sys

df = pd.read_csv('backend/Datasets/dataset.csv')
phish = df[df['Result'] == 1]
legit  = df[df['Result'] == -1]

print("=== SSLfinal_State - Nghich ly quan trong ===")
print("Encoding trong dataset (Mohammad 2015, Table 1):")
print("  -1: HTTP (khong co HTTPS / cer het han)")
print("   0: HTTPS nhung chung chi khong tin cay")
print("   1: HTTPS voi cert hop le")
print()
for v in [-1, 0, 1]:
    subset = df[df['SSLfinal_State'] == v]
    if len(subset) > 0:
        p = (subset['Result'] == 1).sum() / len(subset) * 100
        label = {-1: 'HTTP no SSL', 0: 'HTTPS fake/untrusted', 1: 'HTTPS valid cert'}
        print(f"  SSLfinal_State={v:+d} [{label[v]:<25}]: n={len(subset):5d}, {p:.1f}% phishing")

print()
print("PHAT HIEN: 88.9% cac URL co HTTPS hop le la PHISHING!")
print("Ly do: Phishing hien dai dung LetsEncrypt (mien phi) -> co HTTPS van la phishing")
print("=> Rule 'khong HTTPS = phishing (+20pt)' la SAI theo dataset nay")
print()

print("=== Features co LLR > 0 (thuc su bao hieu phishing) ===")
features = [c for c in df.columns if c not in ['index','Result','Unnamed: 32','Unnamed: 33']]
eps = 1e-6
results = []
for feat in features:
    if feat not in df.columns:
        continue
    p_neg_phish = (phish[feat]==-1).sum() / len(phish)
    p_neg_legit = (legit[feat]==-1).sum() / len(legit)
    llr = np.log((p_neg_phish + eps) / (p_neg_legit + eps))
    cnt_neg = (df[feat]==-1).sum()
    p_phish_given_neg = (df[df[feat]==-1]['Result']==1).sum() / max(1, cnt_neg) * 100
    results.append((feat, llr, p_phish_given_neg))

results.sort(key=lambda x: -x[1])
print(f"  {'Feature':<35} {'LLR':>8}  {'P(phish|feat=-1)':>16}")
print("-" * 65)
for feat, llr, pp in results:
    marker = " <<< EVIDENCE" if llr > 0.05 else ("    neutral" if abs(llr) < 0.05 else "    COUNTER-evidence")
    print(f"  {feat:<35} {llr:>+8.3f}  {pp:>15.1f}%  {marker}")

# Also check LLR for value=1 (safe signal)
print()
print("=== Features co LLR > 0 o CHIEU NGUOC (value=1 bao hieu phishing) ===")
results2 = []
for feat in features:
    if feat not in df.columns:
        continue
    p_pos_phish = (phish[feat]==1).sum() / len(phish)
    p_pos_legit = (legit[feat]==1).sum() / len(legit)
    llr_pos = np.log((p_pos_phish + eps) / (p_pos_legit + eps))
    cnt_pos = (df[feat]==1).sum()
    p_phish_given_pos = (df[df[feat]==1]['Result']==1).sum() / max(1, cnt_pos) * 100
    results2.append((feat, llr_pos, p_phish_given_pos))

results2.sort(key=lambda x: -x[1])
print(f"  {'Feature':<35} {'LLR_pos':>8}  {'P(phish|feat=+1)':>16}")
print("-" * 65)
for feat, llr, pp in results2:
    if llr > 0.05:
        print(f"  {feat:<35} {llr:>+8.3f}  {pp:>15.1f}%  <<< value=1 BIEU HIEN o phishing")
