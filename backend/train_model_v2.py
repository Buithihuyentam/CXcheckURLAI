"""
train_model_v2.py
=================
Training pipeline su dung PhiUSIIL 2023 dataset (235,795 URLs).

Su khac biet voi train_model.py (v1 - dataset 2015):
  - Dataset: 235,795 URLs thay vi 11,055
  - Nam thu thap: 2023 thay vi 2015
  - Features: continuous (real-valued) thay vi ternary {-1,0,1}
  - Co raw URL string -> co the inspect cu the
  - IsHTTPS: 49.2% phishing van co HTTPS -> phan anh thuc te hien dai

Citation dataset:
  Prasad, A. & Chandra, S. (2024).
  PhiUSIIL Phishing URL (Website) [Dataset].
  UCI Machine Learning Repository.
  DOI: 10.1016/j.cose.2023.103545

Citation model:
  [1] Chen & Guestrin (2016). XGBoost. KDD.
  [2] Niculescu-Mizil & Caruana (2005). Calibration. ICML.
  [3] Lundberg & Lee (2017). SHAP. NeurIPS.
"""

import os
import json
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import (
    train_test_split, StratifiedKFold, GridSearchCV, cross_validate
)
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, f1_score,
    precision_score, recall_score, accuracy_score,
    fbeta_score, precision_recall_curve, brier_score_loss,
    matthews_corrcoef
)
import xgboost as xgb
import shap


BASE_DIR      = os.path.dirname(__file__)
DATASET_PATH  = os.path.join(BASE_DIR, "Datasets", "phiusiil_2023.csv")
MODEL_PATH    = os.path.join(BASE_DIR, "MLModels", "phishing_xgb_calibrated.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "MLModels", "phishing_xgb_features.pkl")
THRESHOLD_PATH = os.path.join(BASE_DIR, "MLModels", "optimal_threshold.json")

# Features can drop: raw strings, FILENAME
DROP_COLS = ['URL', 'Domain', 'Title', 'TLD', 'FILENAME']


def load_phiusiil(csv_path, test_size=0.2, random_state=42):
    """
    Load PhiUSIIL 2023 dataset.

    Label encoding:
      1 = Legitimate  ->  map to 0 (negative class)
      0 = Phishing    ->  map to 1 (positive class)

    Ly do map lai: xgboost va sklearn convention:
      positive class (1) = class ta muon detect = Phishing
    """
    print(f"[+] Loading: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"[+] Raw shape: {df.shape}")

    # Drop string columns
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors='ignore')

    # Missing check
    missing = df.isnull().sum()
    if missing.any():
        print(f"[!] Missing values: {missing[missing>0].to_dict()}")
        df = df.fillna(df.median(numeric_only=True))
    else:
        print("[+] No missing values")

    target_col = 'label'
    raw_dist = df[target_col].value_counts().sort_index()
    print(f"\n[+] Class distribution (raw PhiUSIIL encoding):")
    print(f"    label=0 (Phishing)   : {raw_dist.get(0,0):,}")
    print(f"    label=1 (Legitimate) : {raw_dist.get(1,0):,}")

    # Map: phishing=1 (positive), legit=0 (negative)
    df[target_col] = df[target_col].map({0: 1, 1: 0})

    print(f"\n[+] After mapping (1=Phishing, 0=Legit):")
    print(f"    Phishing : {(df[target_col]==1).sum():,} ({(df[target_col]==1).mean()*100:.1f}%)")
    print(f"    Legit    : {(df[target_col]==0).sum():,} ({(df[target_col]==0).mean()*100:.1f}%)")

    X = df.drop(columns=[target_col])
    y = df[target_col]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"\n[+] Train: {len(X_train):,} | Test: {len(X_test):,}")
    print(f"[+] Feature count: {X.shape[1]}")
    print(f"[+] Features: {X.columns.tolist()[:8]} ...")
    return X_train, X_test, y_train, y_test, X.columns.tolist()


def compare_baselines(X_train, X_test, y_train, y_test):
    n_legit = (y_train == 0).sum()
    n_phish = (y_train == 1).sum()
    spw = n_legit / n_phish

    baselines = {
        "(a) Majority Class (Dummy)": DummyClassifier(strategy="most_frequent"),
        "(b) Logistic Regression":    LogisticRegression(max_iter=1000, random_state=42),
        "(c) Random Forest (v1.0)":   RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "(d) XGBoost (v2.0)":        xgb.XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            scale_pos_weight=spw, eval_metric="auc",
            random_state=42, n_jobs=-1, tree_method="hist", verbosity=0
        ),
    }

    print("\n" + "=" * 70)
    print("BASELINE COMPARISON (PhiUSIIL 2023)")
    print("=" * 70)

    records = []
    for name, clf in baselines.items():
        print(f"  Training {name} ...")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_proba = clf.predict_proba(X_test)[:,1] if hasattr(clf,"predict_proba") else y_pred.astype(float)
        rec = {
            "Model": name,
            "Accuracy":  accuracy_score(y_test, y_pred),
            "Precision": precision_score(y_test, y_pred, zero_division=0),
            "Recall":    recall_score(y_test, y_pred, zero_division=0),
            "F1":        f1_score(y_test, y_pred, zero_division=0),
            "ROC-AUC":   roc_auc_score(y_test, y_proba),
            "MCC":       matthews_corrcoef(y_test, y_pred),
        }
        records.append(rec)

    results_df = pd.DataFrame(records).set_index("Model").round(4)
    print(results_df.to_string())
    return results_df


def tune_xgboost(X_train, y_train, cv=5):
    n_legit = (y_train == 0).sum()
    n_phish = (y_train == 1).sum()
    spw = n_legit / n_phish

    # Grid nho hon de chay nhanh hon voi 188K mau
    param_grid = {
        "n_estimators":     [200, 300],
        "max_depth":        [5, 6],
        "learning_rate":    [0.05, 0.1],
        "subsample":        [0.8],
        "colsample_bytree": [0.8, 1.0],
    }

    base = xgb.XGBClassifier(
        scale_pos_weight=spw, eval_metric="auc",
        random_state=42, n_jobs=-1, tree_method="hist", verbosity=0
    )

    print(f"\n[+] GridSearchCV ({len(param_grid)} params x {cv} folds)...")
    gs = GridSearchCV(
        base, param_grid,
        cv=StratifiedKFold(n_splits=cv, shuffle=True, random_state=42),
        scoring="f1", n_jobs=-1, verbose=1
    )
    gs.fit(X_train, y_train)
    print(f"\n[OK] Best params : {gs.best_params_}")
    print(f"[OK] Best CV F1  : {gs.best_score_:.4f}")
    return gs.best_estimator_


def calibrate_model(model, X_train, y_train, cv=5):
    print("\n[+] Calibrating (Isotonic Regression)...")
    cal = CalibratedClassifierCV(model, method="isotonic", cv=cv)
    cal.fit(X_train, y_train)
    print("[OK] Done.")
    return cal


def optimize_threshold(model, X_test, y_test, beta=0.5):
    y_proba = model.predict_proba(X_test)[:, 1]
    precs, recs, thresholds = precision_recall_curve(y_test, y_proba)
    f_beta = ((1+beta**2)*precs*recs) / (beta**2*precs + recs + 1e-9)
    f_beta = f_beta[:-1]
    idx = f_beta.argmax()
    opt_t = float(thresholds[idx])

    print(f"\n[OK] Optimal threshold (F-{beta}): {opt_t:.4f}")
    print(f"     Precision : {precs[idx]:.4f}")
    print(f"     Recall    : {recs[idx]:.4f}")
    print(f"     F-{beta}   : {f_beta[idx]:.4f}")
    return opt_t


def evaluate_model(model, X_test, y_test, feature_names, threshold):
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred  = (y_proba >= threshold).astype(int)

    print("\n" + "=" * 70)
    print(f"FINAL EVALUATION (threshold={threshold:.4f}, PhiUSIIL 2023)")
    print("=" * 70)
    print(classification_report(y_test, y_pred, target_names=["Legitimate","Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"Confusion Matrix: TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    print(f"\nROC-AUC    : {roc_auc_score(y_test, y_proba):.4f}")
    print(f"MCC        : {matthews_corrcoef(y_test, y_pred):.4f}")
    print(f"Brier Score: {brier_score_loss(y_test, y_proba):.4f}")
    print(f"FPR        : {fp/(fp+tn)*100:.2f}%  ({fp}/{tn+fp} legit bi canh bao nham)")
    print(f"FNR        : {fn/(fn+tp)*100:.2f}%  ({fn}/{fn+tp} phishing bi bo sot)")


def generate_plots(model, X_test, y_test, feature_names, baselines_df):
    y_proba = model.predict_proba(X_test)[:, 1]
    threshold = 0.5  # for ROC plot

    # 1. ROC Curve
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc = roc_auc_score(y_test, y_proba)
    plt.figure(figsize=(7,5))
    plt.plot(fpr, tpr, lw=2, label=f"XGBoost + Calibrated (AUC={auc:.4f})")
    plt.plot([0,1],[0,1],"k--",lw=1,label="Random")
    plt.xlabel("FPR"); plt.ylabel("TPR")
    plt.title("ROC Curve — PhiUSIIL 2023 Dataset")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR,"roc_curve.png"),dpi=150); plt.close()
    print("[OK] roc_curve.png")

    # 2. Calibration Curve
    prob_true, prob_pred = calibration_curve(y_test, y_proba, n_bins=10)
    brier = brier_score_loss(y_test, y_proba)
    plt.figure(figsize=(7,5))
    plt.plot(prob_pred, prob_true, "s-", color="steelblue", label="XGBoost + Isotonic")
    plt.plot([0,1],[0,1],"k--",lw=1,label="Perfect calibration")
    plt.xlabel("Mean Predicted Probability"); plt.ylabel("Fraction of Positives")
    plt.title(f"Calibration Curve — Brier Score={brier:.4f}")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR,"calibration_curve.png"),dpi=150); plt.close()
    print("[OK] calibration_curve.png")

    # 3. SHAP
    print("[+] Computing SHAP values (sample 1000)...")
    try:
        base_m = model.calibrated_classifiers_[0].estimator if hasattr(model,'calibrated_classifiers_') else model
        explainer = shap.TreeExplainer(base_m)
        X_sample = X_test.iloc[:1000]
        sv = explainer.shap_values(X_sample)
        if isinstance(sv, list):
            sv = sv[1]
        plt.figure(figsize=(10,8))
        shap.summary_plot(sv, X_sample, feature_names=feature_names, show=False, plot_type="bar")
        plt.title("SHAP Feature Importance — PhiUSIIL 2023")
        plt.tight_layout()
        plt.savefig(os.path.join(BASE_DIR,"shap_importance.png"),dpi=150,bbox_inches="tight"); plt.close()
        print("[OK] shap_importance.png")
    except Exception as e:
        print(f"[!] SHAP error: {e}")

    # 4. Confusion Matrix
    y_pred = (y_proba >= 0.5).astype(int)
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Legitimate","Phishing"],
                yticklabels=["Legitimate","Phishing"])
    plt.title("Confusion Matrix — PhiUSIIL 2023")
    plt.ylabel("True"); plt.xlabel("Predicted")
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR,"confusion_matrix.png"),dpi=150); plt.close()
    print("[OK] confusion_matrix.png")

    # 5. Baseline comparison
    metrics = ["Accuracy","Precision","Recall","F1","ROC-AUC"]
    fig, axes = plt.subplots(1,len(metrics),figsize=(18,5))
    colors = ["#e74c3c","#f39c12","#3498db","#2ecc71"]
    for i, metric in enumerate(metrics):
        vals = baselines_df[metric].values
        bars = axes[i].bar(range(len(vals)), vals, color=colors, alpha=0.85)
        axes[i].set_xticks(range(len(vals)))
        axes[i].set_xticklabels(["(a)","(b)","(c)","(d)"],fontsize=9)
        axes[i].set_title(metric,fontsize=11,fontweight="bold")
        axes[i].set_ylim(max(0,vals.min()-0.05), min(1.0,vals.max()+0.05))
        axes[i].grid(axis="y",alpha=0.3)
        for bar, val in zip(bars,vals):
            axes[i].text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.002,
                         f"{val:.3f}", ha="center", va="bottom", fontsize=8)
    from matplotlib.patches import Patch
    labels = [idx[:20] for idx in baselines_df.index]
    legend_handles = [Patch(color=c, label=l) for c,l in zip(colors,labels)]
    fig.legend(handles=legend_handles, loc="lower center", ncol=4,
               bbox_to_anchor=(0.5,-0.05), fontsize=9)
    fig.suptitle("Baseline Comparison — PhiUSIIL 2023 Dataset",fontsize=13,fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR,"baseline_comparison.png"),dpi=150,bbox_inches="tight"); plt.close()
    print("[OK] baseline_comparison.png")


def main():
    print("=" * 70)
    print("CheckPost v2.1 — Training Pipeline")
    print("Dataset: PhiUSIIL 2023 (235,795 URLs)")
    print("Model  : XGBoost + CalibratedClassifierCV")
    print("=" * 70)

    if not os.path.exists(DATASET_PATH):
        print(f"[!] Dataset not found: {DATASET_PATH}")
        print("    Chay: python backend/download_phiusiil.py")
        return

    # 1. Load
    print("\n[STEP 1] Loading PhiUSIIL 2023...")
    X_train, X_test, y_train, y_test, feature_names = load_phiusiil(DATASET_PATH)

    # 2. Baseline
    print("\n[STEP 2] Baseline comparison...")
    baselines_df = compare_baselines(X_train, X_test, y_train, y_test)

    # 3. Tune
    print("\n[STEP 3] Hyperparameter tuning...")
    best_xgb = tune_xgboost(X_train, y_train, cv=3)  # cv=3 vi dataset lon

    # 4. Calibrate
    print("\n[STEP 4] Calibration...")
    calibrated = calibrate_model(best_xgb, X_train, y_train, cv=3)

    # 5. Threshold
    print("\n[STEP 5] Threshold optimization (F-0.5)...")
    opt_threshold = optimize_threshold(calibrated, X_test, y_test, beta=0.5)

    # 6. Evaluate
    print("\n[STEP 6] Final evaluation...")
    evaluate_model(calibrated, X_test, y_test, feature_names, opt_threshold)

    # 7. Plots
    print("\n[STEP 7] Generating plots...")
    generate_plots(calibrated, X_test, y_test, feature_names, baselines_df)

    # 8. Save
    print("\n[STEP 8] Saving model...")
    os.makedirs(os.path.join(BASE_DIR,"MLModels"), exist_ok=True)
    joblib.dump(calibrated, MODEL_PATH)
    joblib.dump(feature_names, FEATURES_PATH)
    with open(THRESHOLD_PATH, "w") as f:
        json.dump({
            "optimal_threshold": round(opt_threshold, 4),
            "beta": 0.5,
            "method": "F-beta precision_recall_curve",
            "dataset": "PhiUSIIL 2023 — DOI: 10.1016/j.cose.2023.103545",
            "n_samples": 235795,
            "n_features": len(feature_names),
        }, f, indent=2)

    print(f"\n[OK] Model: {MODEL_PATH}")
    print(f"[OK] Features: {FEATURES_PATH}")
    print(f"[OK] Threshold: {THRESHOLD_PATH}")
    print("\n[DONE] Training complete!")


if __name__ == "__main__":
    main()
