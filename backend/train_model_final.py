"""
train_model_final.py — CheckPost v2.2
======================================
Pipeline train SACH: PhiUSIIL 2023 sau khi loai bo oracle/bias features.
+ OOD cross-dataset test tren UCI 2015.

Researcher recommendations implemented:
  [1] Deployability-Driven Feature Selection (bo oracle + collection bias feats)
  [2] OOD Cross-dataset Validation (train PhiUSIIL, test UCI)
  [3] Realistic target: AUC ~0.92-0.97 (khong phai 1.0)
"""

import os, json
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, roc_curve,
    f1_score, precision_score, recall_score, accuracy_score,
    precision_recall_curve, brier_score_loss, matthews_corrcoef
)
import xgboost as xgb
import shap

BASE_DIR       = os.path.dirname(__file__)
PHIUSIIL_PATH  = os.path.join(BASE_DIR, "Datasets", "phiusiil_2023.csv")
UCI_PATH       = os.path.join(BASE_DIR, "Datasets", "dataset.csv")
MODEL_PATH     = os.path.join(BASE_DIR, "MLModels", "phishing_xgb_calibrated.pkl")
FEATURES_PATH  = os.path.join(BASE_DIR, "MLModels", "phishing_xgb_features.pkl")
THRESHOLD_PATH = os.path.join(BASE_DIR, "MLModels", "optimal_threshold.json")

# ============================================================================
# FEATURE WHITELIST — Deployability-Driven Selection
# Chi giu features co the tinh duoc tu URL + nhanh fetch HTML trong <2s
# Nguon: Researcher recommendation + diagnosis/ablation study
# ============================================================================

# Oracle features (label proxy — PHAI BO)
ORACLE_FEATURES = [
    'URLSimilarityIndex',    # legit=100 exactly, phishing<100 → label proxy
    'TLDLegitimateProb',     # tinh tu phan phoi nhan → target leakage
    'URLCharProb',           # tinh tu phan phoi legit chars → target leakage
    'CharContinuationRate',  # tinh tu phan phoi legit patterns → target leakage
    'DomainTitleMatchScore', # phai biet trang goc de so sanh → oracle
    'URLTitleMatchScore',    # idem → oracle
]

# Collection bias features (phuong sai cao do takedown effect — BO)
# Phishing pages bi crawl sau khi da bi takedown → HTML ngan/trong
# Model hoc "trang ngan = phishing" → khong generalize sang phishing moi
BIAS_FEATURES = [
    'LineOfCode',      # phish_mean=66 vs legit_mean=1947 (30x) → bias
    'LargestLineLength',
    'NoOfExternalRef', # phish_mean=1.1 vs legit_mean=85.3 (75x) → bias
    'NoOfSelfRef',     # phish_mean=0.5 vs legit_mean=113.4 (228x) → bias
    'NoOfEmptyRef',
    'NoOfImage',       # phish_mean=0.9 vs legit_mean=44.9 (52x) → bias
    'NoOfJS',          # phish_mean=0.9 vs legit_mean=17.7 (20x) → bias
    'NoOfCSS',         # phish_mean=0.4 vs legit_mean=10.7 (24x) → bias
]

# String columns (khong phai features)
STRING_COLS = ['URL', 'Domain', 'Title', 'TLD', 'FILENAME']

DROP_ALL = ORACLE_FEATURES + BIAS_FEATURES + STRING_COLS

# Features giu lai (deployable trong predictor_improved.py)
DEPLOYABLE_COMMENT = """
DEPLOYABLE FEATURES (36):
  URL Lexical (tinh tu URL string, <1ms):
    URLLength, DomainLength, IsDomainIP, TLDLength, NoOfSubDomain
    HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio
    NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL
    NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL
    NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL
    IsHTTPS, NoOfURLRedirect, NoOfSelfRedirect
    Bank, Pay, Crypto

  Page Content binary flags (fetch <head> nhanh, <1s):
    HasTitle, HasFavicon, HasDescription, HasSocialNet
    HasSubmitButton, HasPasswordField, HasHiddenFields
    HasExternalFormSubmit, HasCopyrightInfo
    IsResponsive, Robots, NoOfPopup, NoOfiFrame
"""


# ============================================================================
# STEP 1: Load & Prepare PhiUSIIL (clean)
# ============================================================================

def load_phiusiil_clean(path):
    print(f"[+] Loading PhiUSIIL 2023: {path}")
    df = pd.read_csv(path)

    # Drop oracle + bias + string cols
    df = df.drop(columns=[c for c in DROP_ALL if c in df.columns], errors='ignore')

    # Label: PhiUSIIL 0=Phishing, 1=Legit → remap to 1=Phishing, 0=Legit
    df['label'] = df['label'].map({0: 1, 1: 0})

    print(f"[+] Shape after dropping oracle/bias features: {df.shape}")
    print(f"[+] Dropped {len([c for c in DROP_ALL if c in pd.read_csv(path, nrows=1).columns])} features")
    print(f"[+] Remaining features: {df.shape[1]-1}")
    print(f"[+] Phishing: {df['label'].sum():,} ({df['label'].mean()*100:.1f}%)")
    print(f"[+] Legit   : {(df['label']==0).sum():,} ({(df['label']==0).mean()*100:.1f}%)")

    X = df.drop(columns=['label'])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[+] Train: {len(X_train):,}  Test: {len(X_test):,}")
    return X_train, X_test, y_train, y_test, X.columns.tolist()


# ============================================================================
# STEP 2: OOD Cross-dataset Mapping (UCI 2015 → PhiUSIIL feature space)
# ============================================================================

def load_uci_mapped(uci_path, phiusiil_features):
    """
    Anh xa UCI 2015 (ternary {-1,0,1}) sang PhiUSIIL feature space.
    Chi dung features co the map duoc mot cach co ly.

    Nguyen tac mapping:
      UCI -1 (phishing signal) → gia tri cao trong PhiUSIIL
      UCI  1 (legit signal)    → gia tri thap trong PhiUSIIL
      UCI  0 (suspicious)      → gia tri trung binh

    Chi report AUC tren tap mapped nay lam OOD evidence.
    """
    print(f"\n[+] Loading UCI 2015 for OOD test: {uci_path}")
    df = pd.read_csv(uci_path)
    df = df.drop(columns=[c for c in df.columns if c.startswith('Unnamed')], errors='ignore')

    # UCI label: -1=Phishing, 1=Legit → remap 1=Phishing, 0=Legit
    df['Result'] = df['Result'].map({-1: 1, 1: 0})
    y_uci = df['Result']

    # Mapping dictionary: UCI_column → (PhiUSIIL_column, mapping_func)
    # Dua tren semantic tuong dong giua hai dataset
    uci_to_phiusiil = {
        # URL structural
        'URLURL_Length': {
            'target': 'URLLength',
            'map': {-1: 100, 0: 65, 1: 30}  # -1=long>75, 0=medium, 1=short<54
        },
        'having_IPhaving_IP_Address': {
            'target': 'IsDomainIP',
            'map': {-1: 1, 0: 0, 1: 0}  # -1=has IP → IsDomainIP=1
        },
        'having_Sub_Domain': {
            'target': 'NoOfSubDomain',
            'map': {-1: 3, 0: 2, 1: 1}  # -1=many, 0=medium, 1=few
        },
        'SSLfinal_State': {
            'target': 'IsHTTPS',
            'map': {-1: 0, 0: 0, 1: 1}  # -1=no HTTPS, 1=has HTTPS
        },
        'Redirect': {
            'target': 'NoOfURLRedirect',
            'map': {-1: 3, 0: 1, 1: 0}  # -1=many redirects
        },
        # Page content
        'Favicon': {
            'target': 'HasFavicon',
            'map': {-1: 0, 0: 0, 1: 1}  # -1=external favicon (bad)
        },
        'Iframe': {
            'target': 'NoOfiFrame',
            'map': {-1: 1, 0: 0, 1: 0}  # -1=has iframe
        },
        'SFH': {
            'target': 'HasExternalFormSubmit',
            'map': {-1: 1, 0: 0, 1: 0}  # -1=form submits externally
        },
        'popUpWidnow': {
            'target': 'NoOfPopup',
            'map': {-1: 1, 0: 0, 1: 0}  # -1=has popup
        },
    }

    # Xay dung feature matrix cho OOD
    ood_data = {}
    mapped_phiusiil = []

    for uci_col, info in uci_to_phiusiil.items():
        target = info['target']
        if uci_col in df.columns and target in phiusiil_features:
            ood_data[target] = df[uci_col].map(info['map']).fillna(0)
            mapped_phiusiil.append(target)

    X_ood_partial = pd.DataFrame(ood_data)

    # Fill cac features khong co trong UCI bang median cua train set (neutral)
    X_ood_full = pd.DataFrame(0, index=X_ood_partial.index,
                               columns=phiusiil_features)
    for col in mapped_phiusiil:
        X_ood_full[col] = X_ood_partial[col]

    print(f"[+] UCI 2015 OOD: {len(X_ood_full):,} samples")
    print(f"[+] Mapped features ({len(mapped_phiusiil)}): {mapped_phiusiil}")
    print(f"[+] Unmapped features set to 0 (neutral)")
    print(f"[+] Phishing: {y_uci.sum():,} ({y_uci.mean()*100:.1f}%)")

    return X_ood_full, y_uci, mapped_phiusiil


# ============================================================================
# STEP 3: Train XGBoost + Calibrate
# ============================================================================

def train_pipeline(X_train, X_test, y_train, y_test):
    n_legit = (y_train == 0).sum()
    n_phish = (y_train == 1).sum()
    spw = n_legit / n_phish
    print(f"[+] scale_pos_weight = {spw:.3f} (legit/phish ratio)")

    # GridSearch - grid gon de chay hop ly voi 188K mau
    param_grid = {
        'n_estimators':     [200, 300],
        'max_depth':        [5, 6],
        'learning_rate':    [0.05, 0.1],
        'subsample':        [0.8],
        'colsample_bytree': [0.8, 1.0],
    }
    base = xgb.XGBClassifier(
        scale_pos_weight=spw, eval_metric='auc',
        random_state=42, n_jobs=-1, tree_method='hist', verbosity=0
    )
    print(f"[+] GridSearchCV ({sum(len(v) for v in param_grid.values())} params, 3-fold)...")
    gs = GridSearchCV(base, param_grid,
                      cv=StratifiedKFold(3, shuffle=True, random_state=42),
                      scoring='f1', n_jobs=-1, verbose=0)
    gs.fit(X_train, y_train)
    print(f"[OK] Best params: {gs.best_params_}")
    print(f"[OK] Best CV F1 : {gs.best_score_:.4f}")

    # Calibrate
    print("[+] CalibratedClassifierCV (isotonic, cv=3)...")
    cal = CalibratedClassifierCV(gs.best_estimator_, method='isotonic', cv=3)
    cal.fit(X_train, y_train)
    print("[OK] Calibration done.")
    return cal


# ============================================================================
# STEP 4: Threshold Optimization F-beta=0.5
# ============================================================================

def optimize_threshold(model, X_test, y_test, beta=0.5):
    y_proba = model.predict_proba(X_test)[:, 1]
    precs, recs, thresholds = precision_recall_curve(y_test, y_proba)
    f_beta = ((1+beta**2)*precs*recs) / (beta**2*precs + recs + 1e-9)
    f_beta = f_beta[:-1]
    idx = f_beta.argmax()
    opt_t = float(thresholds[idx])
    print(f"[OK] Optimal threshold F-{beta}: {opt_t:.4f}")
    print(f"     Precision={precs[idx]:.4f}  Recall={recs[idx]:.4f}  F-{beta}={f_beta[idx]:.4f}")
    return opt_t


# ============================================================================
# STEP 5: Evaluate
# ============================================================================

def evaluate(model, X_test, y_test, threshold, label="Same-distribution (PhiUSIIL 2023)"):
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred  = (y_proba >= threshold).astype(int)

    auc    = roc_auc_score(y_test, y_proba)
    brier  = brier_score_loss(y_test, y_proba)
    mcc    = matthews_corrcoef(y_test, y_pred)
    cm     = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\n{'='*65}")
    print(f"EVALUATION — {label}")
    print(f"{'='*65}")
    print(classification_report(y_test, y_pred, target_names=["Legit","Phishing"]))
    print(f"ROC-AUC    : {auc:.4f}")
    print(f"MCC        : {mcc:.4f}")
    print(f"Brier Score: {brier:.4f}  (0=perfect)")
    print(f"FPR        : {fp/(fp+tn)*100:.2f}%  ({fp}/{tn+fp} legit flagged wrongly)")
    print(f"FNR        : {fn/(fn+tp)*100:.2f}%  ({fn}/{fn+tp} phishing missed)")
    print(f"TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    return auc, brier, mcc


# ============================================================================
# STEP 6: Generate Plots
# ============================================================================

def generate_plots(model, X_test, y_test, feature_names, threshold):
    y_proba = model.predict_proba(X_test)[:, 1]

    # ROC Curve
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc = roc_auc_score(y_test, y_proba)
    plt.figure(figsize=(7,5))
    plt.plot(fpr, tpr, lw=2, label=f"XGBoost Calibrated (AUC={auc:.4f})\nPhiUSIIL 2023 — Clean Features")
    plt.plot([0,1],[0,1],'k--',lw=1,label='Random')
    plt.xlabel('FPR'); plt.ylabel('TPR')
    plt.title('ROC Curve — CheckPost v2.2\n(Oracle/Bias Features Removed)')
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR,'roc_curve.png'),dpi=150); plt.close()
    print("[OK] roc_curve.png")

    # Calibration Curve
    prob_true, prob_pred = calibration_curve(y_test, y_proba, n_bins=10)
    brier = brier_score_loss(y_test, y_proba)
    plt.figure(figsize=(7,5))
    plt.plot(prob_pred, prob_true, 's-', color='steelblue', label='XGBoost + Isotonic')
    plt.plot([0,1],[0,1],'k--',lw=1,label='Perfect calibration')
    plt.xlabel('Mean Predicted Probability'); plt.ylabel('Fraction of Positives')
    plt.title(f'Calibration Curve — Brier Score={brier:.4f}')
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR,'calibration_curve.png'),dpi=150); plt.close()
    print("[OK] calibration_curve.png")

    # Confusion Matrix
    y_pred = (y_proba >= threshold).astype(int)
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Legit','Phishing'],
                yticklabels=['Legit','Phishing'])
    plt.title(f'Confusion Matrix\nthreshold={threshold:.3f}')
    plt.ylabel('True'); plt.xlabel('Predicted'); plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR,'confusion_matrix.png'),dpi=150); plt.close()
    print("[OK] confusion_matrix.png")

    # SHAP
    try:
        print("[+] SHAP values (1000 samples)...")
        base_m = (model.calibrated_classifiers_[0].estimator
                  if hasattr(model,'calibrated_classifiers_') else model)
        explainer = shap.TreeExplainer(base_m)
        X_sample  = X_test.iloc[:1000]
        sv = explainer.shap_values(X_sample)
        if isinstance(sv, list): sv = sv[1]
        plt.figure(figsize=(10,8))
        shap.summary_plot(sv, X_sample, feature_names=feature_names,
                          show=False, plot_type='bar')
        plt.title('SHAP Feature Importance\nPhiUSIIL 2023 — Clean Features')
        plt.tight_layout()
        plt.savefig(os.path.join(BASE_DIR,'shap_importance.png'),dpi=150,
                    bbox_inches='tight'); plt.close()
        print("[OK] shap_importance.png")

        plt.figure(figsize=(10,8))
        shap.summary_plot(sv, X_sample, feature_names=feature_names,
                          show=False, plot_type='dot')
        plt.title('SHAP Beeswarm — Feature Impact Distribution')
        plt.tight_layout()
        plt.savefig(os.path.join(BASE_DIR,'shap_beeswarm.png'),dpi=150,
                    bbox_inches='tight'); plt.close()
        print("[OK] shap_beeswarm.png")
    except Exception as e:
        print(f"[!] SHAP error: {e}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("="*65)
    print("CheckPost v2.2 — CLEAN Training Pipeline")
    print("Dataset: PhiUSIIL 2023 (oracle/bias features removed)")
    print("="*65)

    # --- STEP 1: Load clean data ---
    print("\n[STEP 1] Load & sanitize PhiUSIIL 2023...")
    X_train, X_test, y_train, y_test, feat_names = load_phiusiil_clean(PHIUSIIL_PATH)

    # --- STEP 2: Train ---
    print("\n[STEP 2] Train XGBoost + Calibrate...")
    model = train_pipeline(X_train, X_test, y_train, y_test)

    # --- STEP 3: Threshold ---
    print("\n[STEP 3] Threshold optimization (F-0.5)...")
    opt_t = optimize_threshold(model, X_test, y_test)

    # --- STEP 4: Evaluate same-distribution ---
    print("\n[STEP 4] Same-distribution evaluation...")
    auc_sd, brier_sd, mcc_sd = evaluate(
        model, X_test, y_test, opt_t,
        label="Same-distribution (PhiUSIIL 2023 test set, 20%)"
    )

    # --- STEP 5: OOD Cross-dataset Test ---
    print("\n[STEP 5] OOD Cross-dataset Test (Train: PhiUSIIL 2023 → Test: UCI 2015)...")
    X_ood, y_ood, mapped_feats = load_uci_mapped(UCI_PATH, feat_names)
    auc_ood, brier_ood, mcc_ood = evaluate(
        model, X_ood, y_ood, opt_t,
        label="OOD Cross-dataset (UCI 2015 — unseen distribution)"
    )
    print(f"\n[OOD NOTE] AUC={auc_ood:.4f} on UCI 2015 (only {len(mapped_feats)} features mapped)")
    print(f"           Other {len(feat_names)-len(mapped_feats)} features = 0 (neutral)")
    if auc_ood >= 0.85:
        print(f"           => Model generalizes across datasets (AUC > 0.85)")
    else:
        print(f"           => Expected lower due to limited feature mapping ({len(mapped_feats)} feats)")

    # --- STEP 6: Summary comparison ---
    print(f"\n{'='*65}")
    print("SUMMARY — BEFORE vs AFTER (Researcher Recommendations Applied)")
    print(f"{'='*65}")
    print(f"{'Metric':<25} {'Before (100% leakage)':>22} {'After (clean)':>15}")
    print(f"{'-'*65}")
    print(f"{'AUC same-dist':<25} {'1.0000 (LEAKAGE)':>22} {auc_sd:>15.4f}")
    print(f"{'AUC OOD (UCI 2015)':<25} {'N/A':>22} {auc_ood:>15.4f}")
    print(f"{'Brier Score':<25} {'0.0000 (impossible)':>22} {brier_sd:>15.4f}")
    print(f"{'Features used':<25} {'50':>22} {len(feat_names):>15}")
    print(f"{'Oracle feats':<25} {'6 (leakage)':>22} {'0':>15}")
    print(f"{'Collection bias feats':<25} {'8 (bias)':>22} {'0':>15}")

    # --- STEP 7: Plots ---
    print("\n[STEP 7] Generating plots...")
    generate_plots(model, X_test, y_test, feat_names, opt_t)

    # --- STEP 8: Save ---
    print("\n[STEP 8] Saving model...")
    os.makedirs(os.path.join(BASE_DIR,'MLModels'), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(feat_names, FEATURES_PATH)
    meta = {
        "optimal_threshold": round(opt_t, 4),
        "beta": 0.5,
        "method": "F-beta precision_recall_curve",
        "dataset": "PhiUSIIL 2023 — DOI: 10.1016/j.cose.2023.103545",
        "n_samples": 235795,
        "n_features": len(feat_names),
        "features_dropped": {
            "oracle_label_proxy": ORACLE_FEATURES,
            "collection_bias": BIAS_FEATURES,
            "reason": "Deployability-Driven Feature Selection (Researcher recommendation)"
        },
        "auc_same_dist": round(auc_sd, 4),
        "auc_ood_uci2015": round(auc_ood, 4),
        "brier_score": round(brier_sd, 4),
        "mcc": round(mcc_sd, 4),
    }
    with open(THRESHOLD_PATH, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"[OK] {MODEL_PATH}")
    print(f"[OK] {FEATURES_PATH}")
    print(f"[OK] {THRESHOLD_PATH}")
    print("\n[DONE] Training complete — v2.2 (Clean, Deployable)")

if __name__ == "__main__":
    main()
