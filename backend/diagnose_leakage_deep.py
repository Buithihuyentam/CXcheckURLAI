"""
diagnose_leakage_deep.py
========================
Dieu tra sau: tai sao NoOfExternalRef, NoOfSelfRef, LineOfCode co AUC cao?
Xac dinh chinh xac cai gi gay ra perfect separation.
Tim phuong phap giai quyet DUNG.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

df = pd.read_csv('backend/Datasets/phiusiil_2023.csv')
df['label'] = df['label'].map({0: 1, 1: 0})  # 1=phishing
y = df['label']
DROP = ['URL', 'Domain', 'Title', 'TLD', 'FILENAME']
X_raw = df.drop(columns=['label'] + [c for c in DROP if c in df.columns], errors='ignore')

phish = df[df['label'] == 1]
legit  = df[df['label'] == 0]

# ============================================================
# PHAN TICH 1: URLSimilarityIndex - perfect separator
# ============================================================
print("=" * 70)
print("PHAN TICH 1: URLSimilarityIndex")
print("=" * 70)
feat = 'URLSimilarityIndex'
print(f"  Legit: ALL values = 100.0 (min={legit[feat].min()}, max={legit[feat].max()})")
print(f"  Phishing: mean={phish[feat].mean():.2f}, min={phish[feat].min():.2f}, max={phish[feat].max():.2f}")
print()
print("  => Day la feature tinh toan BANG CACH SO SANH URL VOI DATABASE LEGIT")
print("  => Neu URL khong co trong DB legit -> score thap -> bieu hien phishing")
print("  => Day la CIRCULAR REASONING / LABEL LEAKAGE:")
print("     Feature duoc xay dung dua tren nhan (legit/phishing) => khong the dung de train!")

# ============================================================
# PHAN TICH 2: Content-based features - phuong phap thu thap
# ============================================================
print()
print("=" * 70)
print("PHAN TICH 2: CONTENT-BASED FEATURES (LineOfCode, NoOfExternalRef, etc.)")
print("=" * 70)
content_feats = ['LineOfCode', 'NoOfExternalRef', 'NoOfSelfRef', 'NoOfImage',
                 'NoOfJS', 'NoOfCSS', 'HasSocialNet', 'HasCopyrightInfo',
                 'LargestLineLength', 'IsResponsive', 'HasDescription']
for feat in content_feats:
    if feat in df.columns:
        p_val = phish[feat].mean()
        l_val = legit[feat].mean()
        ratio = l_val / max(p_val, 0.001)
        print(f"  {feat:<25} phish={p_val:>10.2f}  legit={l_val:>10.2f}  legit/phish={ratio:.1f}x")

print()
print("  => Ly do: Phishing site thu thap nam 2023 nhieu khi la:")
print("     a) Trang don gian (it JS, CSS, image) -> LineOfCode thap")
print("     b) Trang bi takedown -> khong load duoc -> LineOfCode = 0 hoac rat nho")
print("     c) Bot crawl khi trang van con hoat dong -> data bi lech")
print()
print("  => DAY CHINH LA VAN DE:")
print("     PhiUSIIL crawl BOTH legit va phishing URL cung luc.")
print("     Nhieu phishing URL da bi takedown -> HTML rat ngan/trong.")
print("     Day khong phai 'leakage' theo nghia ky thuat, nhung la")
print("     'dataset bias': model hoc duoc rang 'trang ngan = phishing'")
print("     -> Trong thuc te, phishing moi (chua bi takedown) co HTML binh thuong!")

# ============================================================
# PHAN TICH 3: Test khong co CA URL-based VA content-based features
# ============================================================
print()
print("=" * 70)
print("PHAN TICH 3: AUC VOI CHI FEATURES URL-STRUCTURE THUAN TUY")
print("  (features tinh tu URL string, khong can fetch HTML)")
print("=" * 70)

# URL-structure features only (co the tinh ma khong can HTML)
URL_STRUCT_FEATS = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength',
    'URLSimilarityIndex',  # se bo sau
    'TLDLegitimateProb', 'URLCharProb', 'CharContinuationRate',
    'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
    'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
    'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
    'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS',
    'NoOfURLRedirect', 'NoOfSelfRedirect',
    'Bank', 'Pay', 'Crypto',
]
# Loc features co trong dataset
URL_STRUCT_FEATS = [f for f in URL_STRUCT_FEATS if f in X_raw.columns]

# Content-based features (can fetch HTML)
CONTENT_FEATS = [f for f in X_raw.columns if f not in URL_STRUCT_FEATS]

print(f"\n  URL-structure features ({len(URL_STRUCT_FEATS)}): {URL_STRUCT_FEATS}")
print(f"\n  Content-based features ({len(CONTENT_FEATS)}): {CONTENT_FEATS}")

# Sample nho
np.random.seed(42)
idx = np.random.choice(len(X_raw), 30000, replace=False)
X_s = X_raw.iloc[idx].reset_index(drop=True)
y_s = y.iloc[idx].reset_index(drop=True)
Xtr, Xte, ytr, yte = train_test_split(X_s, y_s, test_size=0.25, stratify=y_s, random_state=42)

def quick_xgb_auc(Xtr, Xte, ytr, yte, cols):
    m = xgb.XGBClassifier(n_estimators=100, max_depth=5, n_jobs=-1,
                           tree_method='hist', verbosity=0, eval_metric='auc', random_state=42)
    m.fit(Xtr[cols], ytr)
    return roc_auc_score(yte, m.predict_proba(Xte[cols])[:,1])

tests = {
    "All 50 features":                   X_raw.columns.tolist(),
    "URL-struct only (incl. Similarity)": URL_STRUCT_FEATS,
    "URL-struct MINUS URLSimilarityIndex": [f for f in URL_STRUCT_FEATS if f != 'URLSimilarityIndex'],
    "Content-based only":                CONTENT_FEATS,
    "Content MINUS LineOfCode/Refs":     [f for f in CONTENT_FEATS
                                          if f not in ['LineOfCode','NoOfExternalRef','NoOfSelfRef','LargestLineLength']],
}

print()
print(f"{'Feature set':<50} {'AUC':>8}  Verdict")
print("-" * 75)
for name, cols in tests.items():
    cols = [c for c in cols if c in Xtr.columns]
    if not cols:
        continue
    auc = quick_xgb_auc(Xtr, Xte, ytr, yte, cols)
    if auc >= 0.9999:
        verdict = "LEAKAGE / BIAS"
    elif auc >= 0.99:
        verdict = "suspect (very high)"
    elif auc >= 0.95:
        verdict = "strong (possibly OK)"
    elif auc >= 0.90:
        verdict = "realistic (good)"
    else:
        verdict = "realistic (moderate)"
    print(f"{name:<50} {auc:>8.6f}  {verdict}")

# ============================================================
# PHAN TICH 4: URLSimilarityIndex - doc paper de hieu ro
# ============================================================
print()
print("=" * 70)
print("PHAN TICH 4: BAN CHAT CUA URLSimilarityIndex")
print("=" * 70)
print()
print("Theo paper PhiUSIIL (Prasad & Chandra 2024, Computers & Security):")
print()
print("  URLSimilarityIndex = so sanh URL voi tap hop URL legit trong DATABASE")
print("  => Neu URL giong legit DB (e.g. google.com) -> score cao (~100)")
print("  => Phishing URL moi khong co trong legit DB -> score thap")
print()
print("  KHU VUC NAO GAY RA LEAKAGE:")
print("  - Legit URLs trong dataset: ALL have URLSimilarityIndex = 100.000")
print("  - Phishing URLs: mean = 49.6 (khong co trong DB)")
print()
print("  KET LUAN: URLSimilarityIndex la PROXY CUA NHAN (label proxy)")
print("  Neu URL la legit -> co trong DB -> score = 100")
print("  Neu URL la phishing -> khong co trong DB -> score < 100")
print("  => PHAI BO FEATURE NAY 100%")
print()
print("  Tuong tu: TLDLegitimateProb, URLCharProb, CharContinuationRate")
print("  duoc tinh tu distribution cua LEGIT URLs -> la meta-features cua nhan")

# ============================================================
# PHAN TICH 5: Giai phap triet de
# ============================================================
print()
print("=" * 70)
print("GIAI PHAP TRIET DE")
print("=" * 70)
print()
print("LOAI BO (khong duoc dung):")
print("  [PROXY]   URLSimilarityIndex  — tinh tu legit URL database")
print("  [PROXY]   TLDLegitimateProb   — tinh tu distribution legit TLDs")
print("  [PROXY]   URLCharProb         — tinh tu distribution legit URL chars")
print("  [PROXY]   CharContinuationRate — tinh tu distribution legit char patterns")
print("  [BIAS]    LineOfCode           — phuong sai cao do takedown bias")
print("  [BIAS]    NoOfExternalRef      — idem")
print("  [BIAS]    NoOfSelfRef          — idem")
print("  [BIAS]    LargestLineLength    — idem")
print()
print("  GHI CHU VE CONTENT FEATURES (LineOfCode, etc.):")
print("  Khong phai 'data leakage' theo nghia ky thuat (nhan khong lo ra truc tiep)")
print("  Nhung la 'DATASET COLLECTION BIAS':")
print("    - Phishing URL bi crawl SAU khi bi report -> co khi da bi takedown")
print("    - Trang bi takedown -> tra ve 404 hoac HTML rat ngan")
print("    - Model hoc: 'trang ngan = phishing'")
print("    - Thuc te: phishing moi chua bi takedown co HTML day du")
print("  => Dung trong lab tot, nhung real-world performance se kem hon nhieu")
print()
print("GIU LAI (features URL-structure, tinh tu URL string thuan tuy):")
url_keep = [f for f in URL_STRUCT_FEATS
            if f not in ['URLSimilarityIndex','TLDLegitimateProb','URLCharProb','CharContinuationRate']]
for f in url_keep:
    print(f"  [KEEP] {f}")
print()
print("GIU LAI CONTENT FEATURES VOI CAO BANH:")
content_safe = ['IsHTTPS', 'HasTitle', 'HasFavicon', 'HasSubmitButton',
                'HasPasswordField', 'HasHiddenFields', 'HasExternalFormSubmit',
                'HasSocialNet', 'HasCopyrightInfo', 'HasDescription',
                'IsResponsive', 'Robots', 'NoOfPopup', 'NoOfiFrame',
                'Bank', 'Pay', 'Crypto', 'NoOfURLRedirect', 'NoOfSelfRedirect']
for f in content_safe:
    if f in df.columns:
        print(f"  [KEEP_CAUTIOUS] {f}")

print()
print("PHUONG PHAP TRAIN LAI:")
print("  1. Bo 4 'proxy label' features")
print("  2. Bo 4 'collection bias' content features")  
print("  3. Dung tap features con lai (URL-struct + safe content)")
print("  4. Xem AUC co con gan 1.0 khong (neu co -> van co gi do sai)")
print("  5. Ky vong: AUC ~ 0.95-0.98 la realistic cho URL-only features")
