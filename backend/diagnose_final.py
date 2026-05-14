"""
diagnose_final.py
=================
Tim nguyen nhan cot loi: tai sao sau khi bo URLSimilarityIndex,
AUC van con 0.9986 (gan nhu perfect)?
Test tung feature mot theo phuong phap ablation study thuc su.
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

df = pd.read_csv('backend/Datasets/phiusiil_2023.csv')
df['label'] = df['label'].map({0: 1, 1: 0})
y = df['label']
phish = df[df['label'] == 1]
legit  = df[df['label'] == 0]

DROP = ['URL', 'Domain', 'Title', 'TLD', 'FILENAME',
        'URLSimilarityIndex', 'TLDLegitimateProb',
        'URLCharProb', 'CharContinuationRate']
X = df.drop(columns=['label'] + [c for c in DROP if c in df.columns], errors='ignore')
print(f"Features sau khi bo proxy: {X.shape[1]}")
print(f"Features: {X.columns.tolist()}")
print()

# Sample 40K de nhanh
np.random.seed(42)
idx = np.random.choice(len(X), 40000, replace=False)
Xs = X.iloc[idx].reset_index(drop=True)
ys = y.iloc[idx].reset_index(drop=True)
Xtr, Xte, ytr, yte = train_test_split(Xs, ys, test_size=0.25, stratify=ys, random_state=42)

def quick_auc(cols):
    cols = [c for c in cols if c in Xtr.columns]
    if not cols: return 0.0
    m = xgb.XGBClassifier(n_estimators=100, max_depth=5, n_jobs=-1,
                           tree_method='hist', verbosity=0, eval_metric='auc', random_state=42)
    m.fit(Xtr[cols], ytr)
    return roc_auc_score(yte, m.predict_proba(Xte[cols])[:,1])

ALL_FEATS = X.columns.tolist()

print("=" * 70)
print("ABLATION STUDY: Lan luot bo tung feature, xem AUC thay doi bao nhieu")
print("(AUC cao nhat = feature do la nguon leakage/bias chinh)")
print("=" * 70)

base_auc = quick_auc(ALL_FEATS)
print(f"Base AUC (all {len(ALL_FEATS)} features): {base_auc:.6f}")
print()

results = []
for feat in ALL_FEATS:
    remaining = [f for f in ALL_FEATS if f != feat]
    auc = quick_auc(remaining)
    delta = base_auc - auc
    results.append((feat, auc, delta))

results.sort(key=lambda x: -x[2])
print(f"{'Feature dropped':<35} {'AUC w/o':<12} {'Delta (drop)':<14} Verdict")
print("-" * 75)
for feat, auc, delta in results:
    if delta > 0.01:
        verdict = ">>> KEY CONTRIBUTOR"
    elif delta > 0.001:
        verdict = ">> notable"
    elif delta < -0.001:
        verdict = "  (removing helps?)"
    else:
        verdict = "  minimal"
    print(f"{feat:<35} {auc:<12.6f} {delta:>+10.6f}   {verdict}")

print()
print("=" * 70)
print("PHAN TICH PHAN PHOI CAC FEATURE QUAN TRONG NHAT")
print("=" * 70)

# Top 10 contributors
top_feats = [f for f, _, d in results if d > 0.002]
for feat in top_feats[:10]:
    p = phish[feat]
    l = legit[feat]
    print(f"\n{feat}:")
    print(f"  Phishing: mean={p.mean():.3f}  median={p.median():.3f}  "
          f"q25={p.quantile(0.25):.3f}  q75={p.quantile(0.75):.3f}")
    print(f"  Legit   : mean={l.mean():.3f}  median={l.median():.3f}  "
          f"q25={l.quantile(0.25):.3f}  q75={l.quantile(0.75):.3f}")
    pct_zero_phish = (p == 0).mean() * 100
    pct_zero_legit = (l == 0).mean() * 100
    print(f"  %zero phishing={pct_zero_phish:.1f}%  %zero legit={pct_zero_legit:.1f}%")
    if pct_zero_phish > 60 and pct_zero_legit < 20:
        print(f"  VERDICT: {pct_zero_phish:.0f}% phishing = 0 vs {pct_zero_legit:.0f}% legit = 0")
        print(f"           => COLLECTION BIAS (phishing da bi takedown khi crawl)")
    elif pct_zero_legit > 60 and pct_zero_phish < 20:
        print(f"  VERDICT: Nguoc lai - legit hay = 0")
    else:
        print(f"  VERDICT: Natural feature (no obvious bias)")

print()
print("=" * 70)
print("TEST CUOI: URL-STRUCTURE ONLY (khong co HTML features)")
print("=" * 70)
URL_ONLY = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
    'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
    'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
    'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
    'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL',
    'IsHTTPS', 'NoOfURLRedirect', 'NoOfSelfRedirect',
    'Bank', 'Pay', 'Crypto',
]
URL_ONLY = [f for f in URL_ONLY if f in X.columns]
auc_url = quick_auc(URL_ONLY)
print(f"URL-structure only ({len(URL_ONLY)} features): AUC = {auc_url:.6f}")

# Content features that are binary flags (less bias-prone)
BINARY_CONTENT = [
    'IsHTTPS', 'HasTitle', 'HasFavicon', 'HasSubmitButton', 'HasPasswordField',
    'HasHiddenFields', 'HasExternalFormSubmit', 'HasSocialNet', 'HasCopyrightInfo',
    'HasDescription', 'IsResponsive', 'Robots', 'NoOfPopup', 'NoOfiFrame',
]
BINARY_CONTENT = [f for f in BINARY_CONTENT if f in X.columns]
auc_bin = quick_auc(URL_ONLY + BINARY_CONTENT)
print(f"URL-struct + binary content ({len(URL_ONLY+BINARY_CONTENT)} features): AUC = {auc_bin:.6f}")

# All minus heavily biased content
BIASED = ['LineOfCode', 'LargestLineLength', 'NoOfExternalRef', 'NoOfSelfRef',
          'NoOfImage', 'NoOfJS', 'NoOfCSS', 'NoOfEmptyRef']
CLEAN = [f for f in ALL_FEATS if f not in BIASED]
auc_clean = quick_auc(CLEAN)
print(f"All MINUS biased content ({len(CLEAN)} features): AUC = {auc_clean:.6f}")

print()
print("=" * 70)
print("KET LUAN VA KHUYEN NGHI CUOI CUNG")
print("=" * 70)
print(f"""
Tinh trang:
  - AUC = 1.0000 voi all features: DO COLLECTION BIAS
  - URLSimilarityIndex: LABEL PROXY (100% legit = 100, ~50% phishing < 100)
  - TLDLegitimateProb/URLCharProb/CharContinuationRate: META-LABEL FEATURES
  - LineOfCode/NoOfExternalRef/NoOfSelfRef/NoOfImage/NoOfJS/NoOfCSS:
    COLLECTION BIAS (phishing pages crawled after takedown -> HTML empty)

Giai phap triet de:
  Option A (MANH ME NHAT): Train chi voi URL-structure features (23 feats)
    Pro: Khong co bias, AUC ~ 0.85-0.92 la realistic
    Con: Khong dung binary content features
    AUC du kien: {auc_url:.4f}

  Option B (CA BU): Train voi URL-struct + binary content flags
    Pro: Them thong tin tu trang web, khong co bias nghiem trong
    Con: Binary flags van co it bias (False = trang khong load duoc)
    AUC du kien: {auc_bin:.4f}

  Option C (THUC TE): Bo het count/size-based content features
    Pro: Van dung duoc nhieu features, less bias
    Con: Van co some bias tu binary flags
    AUC du kien: {auc_clean:.4f}

KHUYEN NGHI FINAL:
  => Option B la hop ly nhat cho khoa luan nay
  => Loai bo: URLSimilarityIndex, TLDLegitimateProb, URLCharProb,
              CharContinuationRate, LineOfCode, LargestLineLength,
              NoOfExternalRef, NoOfSelfRef, NoOfImage, NoOfJS, NoOfCSS, NoOfEmptyRef
  => Giu lai: {len(URL_ONLY + BINARY_CONTENT)} features
  => Can ghi ro LIMITATION trong thesis: model co the overestimate performance
     voi phishing pages chua bi takedown (bias cua dataset)
""")
