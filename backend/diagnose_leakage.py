"""
diagnose_leakage.py
===================
Dieu tra nguyen nhan accuracy=1.0 tren PhiUSIIL 2023.
Phan tich tung feature de xac dinh nguon goc leakage.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier
import warnings
warnings.filterwarnings('ignore')

df = pd.read_csv('backend/Datasets/phiusiil_2023.csv')

# Map label: 0=phishing->1, 1=legit->0
df['label'] = df['label'].map({0: 1, 1: 0})
y = df['label']

DROP = ['URL', 'Domain', 'Title', 'TLD', 'FILENAME']
X_raw = df.drop(columns=['label'] + [c for c in DROP if c in df.columns], errors='ignore')

print("=" * 70)
print("DIEU TRA NGUYEN NHAN ACCURACY = 1.0000")
print("=" * 70)
print(f"Dataset: {len(df):,} samples x {X_raw.shape[1]} features")
print(f"Phishing: {y.sum():,} ({y.mean()*100:.1f}%)")
print()

# ============================================================
# Test 1: Tung feature mot minh, dung Decision Tree depth=1
# Neu 1 feature alone -> AUC gan 1.0 => day la leakage feature
# ============================================================
print("=" * 70)
print("TEST 1: ROC-AUC CUA TUNG FEATURE (Decision Tree depth=1)")
print("  Feature co AUC > 0.95 voi depth=1 = suspect leakage")
print("=" * 70)

X_train, X_test, y_train, y_test = train_test_split(
    X_raw, y, test_size=0.2, random_state=42, stratify=y
)

single_aucs = []
for col in X_raw.columns:
    try:
        clf = DecisionTreeClassifier(max_depth=1, random_state=42)
        clf.fit(X_train[[col]], y_train)
        proba = clf.predict_proba(X_test[[col]])[:, 1]
        auc = roc_auc_score(y_test, proba)
        single_aucs.append((col, auc))
    except Exception as e:
        single_aucs.append((col, 0.0))

single_aucs.sort(key=lambda x: -x[1])
print(f"\n{'Feature':<35} {'AUC (depth=1)':>14}  {'Risk'}")
print("-" * 65)
for feat, auc in single_aucs:
    if auc >= 0.99:
        risk = ">>> LEAKAGE (near-perfect solo predictor)"
    elif auc >= 0.95:
        risk = ">> HIGH SUSPECT"
    elif auc >= 0.85:
        risk = "> STRONG predictor"
    elif auc >= 0.70:
        risk = "  moderate"
    else:
        risk = "  weak"
    print(f"{feat:<35} {auc:>14.4f}  {risk}")

# ============================================================
# Test 2: Phan tich phan phoi cua top leakage features
# ============================================================
print()
print("=" * 70)
print("TEST 2: PHAN PHOI CUA TOP FEATURES THEO CLASS")
print("=" * 70)

top_features = [f for f, auc in single_aucs if auc >= 0.95]
phish = df[df['label'] == 1]
legit  = df[df['label'] == 0]

for feat in top_features:
    print(f"\n{feat}:")
    print(f"  Phishing  — mean={phish[feat].mean():.4f}  std={phish[feat].std():.4f}  "
          f"min={phish[feat].min():.2f}  max={phish[feat].max():.2f}")
    print(f"  Legit     — mean={legit[feat].mean():.4f}  std={legit[feat].std():.4f}  "
          f"min={legit[feat].min():.2f}  max={legit[feat].max():.2f}")
    # Overlap analysis
    p_min, p_max = phish[feat].min(), phish[feat].max()
    l_min, l_max = legit[feat].min(), legit[feat].max()
    overlap_low  = max(p_min, l_min)
    overlap_high = min(p_max, l_max)
    has_overlap = overlap_low < overlap_high
    print(f"  Overlap range: [{overlap_low:.2f}, {overlap_high:.2f}] — {'YES overlap' if has_overlap else 'NO OVERLAP (perfect separation!)'}")

# ============================================================
# Test 3: Loai bo tung nhom features, xem AUC con bao nhieu
# ============================================================
print()
print("=" * 70)
print("TEST 3: XGBoost AUC KHI LOAi BO NHOM FEATURES")
print("=" * 70)

import xgboost as xgb

def quick_auc(X_tr, X_te, y_tr, y_te):
    m = xgb.XGBClassifier(
        n_estimators=100, max_depth=4, learning_rate=0.1,
        n_jobs=-1, tree_method='hist', verbosity=0, eval_metric='auc', random_state=42
    )
    m.fit(X_tr, y_tr)
    return roc_auc_score(y_te, m.predict_proba(X_te)[:,1])

# Nhom features theo tinh chat
groups = {
    "All features (baseline)": [],  # dung het
    "Drop URLSimilarityIndex":         ["URLSimilarityIndex"],
    "Drop TLDLegitimateProb":          ["TLDLegitimateProb"],
    "Drop URLCharProb":                ["URLCharProb"],
    "Drop CharContinuationRate":       ["CharContinuationRate"],
    "Drop DomainTitleMatchScore":      ["DomainTitleMatchScore"],
    "Drop URLTitleMatchScore":         ["URLTitleMatchScore"],
    "Drop ALL 'similarity/prob' feats": [
        "URLSimilarityIndex", "TLDLegitimateProb", "URLCharProb",
        "CharContinuationRate", "DomainTitleMatchScore", "URLTitleMatchScore"
    ],
}

# Sample nho hon de chay nhanh
SAMPLE = 20000
idx = np.random.RandomState(42).choice(len(X_train), SAMPLE, replace=False)
Xtr_s = X_train.iloc[idx].reset_index(drop=True)
ytr_s = y_train.iloc[idx].reset_index(drop=True)
Xte_s = X_test.iloc[:5000].reset_index(drop=True)
yte_s = y_test.iloc[:5000].reset_index(drop=True)

for name, drop_feats in groups.items():
    cols = [c for c in Xtr_s.columns if c not in drop_feats]
    auc = quick_auc(Xtr_s[cols], Xte_s[cols], ytr_s, yte_s)
    marker = "<<< LEAKAGE CONFIRMED" if auc >= 0.9999 else ("  realistic" if auc < 0.98 else "  still very high")
    print(f"  {name:<45} AUC={auc:.6f}  {marker}")
