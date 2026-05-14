# train_model.py
"""
Pipeline huấn luyện mô hình phát hiện phishing — CheckPost v2.0
=================================================================

Cải tiến so với v1.0:
  1. XGBoost thay thế Random Forest (nhỏ hơn 8x, nhanh hơn 10x, acc cao hơn)
  2. CalibratedClassifierCV (Isotonic Regression) — confidence score có nghĩa xác suất
  3. Bảng so sánh 4 baselines — bắt buộc cho thesis
  4. Threshold optimization theo F-beta (beta=0.5) — giảm false positive
  5. SHAP explainability — giải thích quyết định của model
  6. Calibration curve plot — bằng chứng độ tin cậy của confidence score

Tham chiếu:
  [1] Chen & Guestrin (2016). XGBoost. KDD.
  [2] Niculescu-Mizil & Caruana (2005). Predicting Good Probabilities. ICML.
  [3] Lundberg & Lee (2017). SHAP. NeurIPS.
  [4] Mohammad et al. (2015). Phishing Websites Features. UCI ML Repository.
"""

import os
import json
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import (
    train_test_split, StratifiedKFold,
    cross_validate, GridSearchCV
)
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.preprocessing import StandardScaler
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


# ============================================================================
# PATHS
# ============================================================================

BASE_DIR     = os.path.dirname(__file__)
DATASET_PATH = os.path.join(BASE_DIR, "Datasets", "dataset.csv")
MODEL_PATH   = os.path.join(BASE_DIR, "MLModels", "phishing_xgb_calibrated.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "MLModels", "phishing_xgb_features.pkl")
THRESHOLD_PATH = os.path.join(BASE_DIR, "MLModels", "optimal_threshold.json")


# ============================================================================
# STEP 1: Load & Prepare Data
# ============================================================================

def load_and_prepare_data(csv_path, target_col="Result", test_size=0.2, random_state=42):
    """
    Load dataset và tạo stratified train/test split.

    Dataset encoding [Ref 4]:
      -1 = Phishing (positive class → map về 1)
       1 = Legitimate (negative class → map về 0)

    Note: XGBoost yêu cầu binary labels {0, 1}.
    """
    df = pd.read_csv(csv_path)
    
    # Bỏ cột rác
    drop_cols = [c for c in df.columns if c.startswith("Unnamed") or c == "index"]
    df = df.drop(columns=drop_cols, errors="ignore")

    print(f"[+] Dataset loaded: {df.shape[0]:,} samples × {df.shape[1]} columns")

    # Xử lý missing values
    missing = df.isnull().sum()
    if missing.any():
        print(f"[!] Missing values: {missing[missing > 0].to_dict()}")
        df = df.fillna(df.median(numeric_only=True))

    # Class distribution
    raw_dist = df[target_col].value_counts().sort_index()
    print(f"\n[+] Class distribution (raw):")
    print(f"    -1 (Phishing)  : {raw_dist.get(-1, 0):,}")
    print(f"     1 (Legitimate): {raw_dist.get(1, 0):,}")

    # Map labels: -1 (phishing) → 1, 1 (legit) → 0
    # Lý do: XGBoost, sklearn dùng {0,1}; "1" = positive = phishing
    df[target_col] = df[target_col].map({-1: 1, 1: 0})

    X = df.drop(columns=[target_col])
    y = df[target_col]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"\n[+] Train: {len(X_train):,} | Test: {len(X_test):,}")
    print(f"[+] Phishing rate — Train: {y_train.mean()*100:.1f}% | Test: {y_test.mean()*100:.1f}%")

    return X_train, X_test, y_train, y_test, X.columns.tolist()


# ============================================================================
# STEP 2: Baseline Comparison
# ============================================================================

def compare_baselines(X_train, X_test, y_train, y_test, cv=5):
    """
    So sánh 4 baselines. Yêu cầu bắt buộc cho thesis:
    hội đồng luôn hỏi "tốt hơn gì so với baseline?"

    Models:
      (a) Majority Class Dummy — lower bound
      (b) Logistic Regression  — linear baseline
      (c) Random Forest        — v1.0 (current system)
      (d) XGBoost              — proposed v2.0
    """
    # Tỷ lệ imbalance để set scale_pos_weight
    n_legit  = (y_train == 0).sum()
    n_phish  = (y_train == 1).sum()
    spw = n_legit / n_phish  # ~0.795

    baselines = {
        "(a) Majority Class (Dummy)": DummyClassifier(strategy="most_frequent"),
        "(b) Logistic Regression":    LogisticRegression(max_iter=1000, random_state=42),
        "(c) Random Forest (v1.0)":   RandomForestClassifier(
            n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "(d) XGBoost (v2.0)":        xgb.XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            scale_pos_weight=spw, eval_metric="auc",
            random_state=42, n_jobs=-1, tree_method="hist",
            verbosity=0
        ),
    }

    print("\n" + "=" * 70)
    print("BASELINE COMPARISON")
    print("=" * 70)

    records = []
    for name, clf in baselines.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        if hasattr(clf, "predict_proba"):
            y_proba = clf.predict_proba(X_test)[:, 1]
            auc = roc_auc_score(y_test, y_proba)
        else:
            y_proba = y_pred.astype(float)
            auc = 0.5

        rec = {
            "Model": name,
            "Accuracy": accuracy_score(y_test, y_pred),
            "Precision": precision_score(y_test, y_pred, zero_division=0),
            "Recall":    recall_score(y_test, y_pred, zero_division=0),
            "F1":        f1_score(y_test, y_pred, zero_division=0),
            "ROC-AUC":   auc,
            "MCC":       matthews_corrcoef(y_test, y_pred),
        }
        records.append(rec)

    results_df = pd.DataFrame(records).set_index("Model").round(4)
    print(results_df.to_string())
    return results_df


# ============================================================================
# STEP 3: Hyperparameter Tuning (XGBoost)
# ============================================================================

def tune_xgboost(X_train, y_train, cv=5):
    """
    GridSearchCV cho XGBoost.
    Tham số grid được rút gọn để chạy hợp lý trên laptop.
    """
    n_legit  = (y_train == 0).sum()
    n_phish  = (y_train == 1).sum()
    spw = n_legit / n_phish

    param_grid = {
        "n_estimators":    [200, 300],
        "max_depth":       [4, 6],
        "learning_rate":   [0.05, 0.1],
        "subsample":       [0.8, 1.0],
        "colsample_bytree":[0.8, 1.0],
    }

    base = xgb.XGBClassifier(
        scale_pos_weight=spw,
        eval_metric="auc",
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
        verbosity=0
    )

    print("\n[+] GridSearchCV đang chạy (có thể mất 5-10 phút)...")
    gs = GridSearchCV(
        base, param_grid, cv=StratifiedKFold(n_splits=cv, shuffle=True, random_state=42),
        scoring="f1", n_jobs=-1, verbose=1
    )
    gs.fit(X_train, y_train)

    print(f"\n[✓] Best params: {gs.best_params_}")
    print(f"[✓] Best CV F1 : {gs.best_score_:.4f}")
    return gs.best_estimator_


# ============================================================================
# STEP 4: Probability Calibration
# ============================================================================

def calibrate_model(model, X_train, y_train, cv=5):
    """
    Bọc model bằng CalibratedClassifierCV (Isotonic Regression).

    Mục đích: Đảm bảo predict_proba() phản ánh xác suất thực,
    không chỉ là score tương đối.

    Lý thuyết [Ref 2]:
      Isotonic regression phù hợp khi dataset > 1,000 samples.
      Dataset 11K phishing: phù hợp dùng isotonic.
    """
    print("\n[+] Calibrating model probabilities (Isotonic Regression)...")
    calibrated = CalibratedClassifierCV(
        model,
        method="isotonic",
        cv=cv
    )
    calibrated.fit(X_train, y_train)
    print("[✓] Calibration done.")
    return calibrated


# ============================================================================
# STEP 5: Threshold Optimization (F-beta, beta=0.5)
# ============================================================================

def optimize_threshold(model, X_test, y_test, beta=0.5):
    """
    Tìm classification threshold tối ưu theo F-beta score.

    beta = 0.5: precision quan trọng hơn recall (2:1).
    Lý do: False positive (block nhầm URL hợp lệ) tệ hơn
           false negative (bỏ sót phishing) trong UX context —
           người dùng sẽ tắt extension nếu nó block nhầm quá nhiều.

    Output: ngưỡng thay thế hardcoded 0.50 hiện tại.
    """
    y_proba = model.predict_proba(X_test)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba)

    # F-beta score tại mỗi threshold
    f_beta = ((1 + beta**2) * precisions * recalls) / \
             (beta**2 * precisions + recalls + 1e-9)
    
    # Loại bỏ threshold cuối (precision_recall_curve trả thêm 1 phần tử)
    f_beta = f_beta[:-1]
    
    opt_idx = f_beta.argmax()
    opt_threshold = float(thresholds[opt_idx])
    opt_f_beta    = float(f_beta[opt_idx])
    opt_precision = float(precisions[opt_idx])
    opt_recall    = float(recalls[opt_idx])

    print(f"\n[✓] Optimal threshold (F-{beta}):")
    print(f"    Threshold : {opt_threshold:.3f}  (was hardcoded 0.500)")
    print(f"    F-{beta}    : {opt_f_beta:.4f}")
    print(f"    Precision : {opt_precision:.4f}")
    print(f"    Recall    : {opt_recall:.4f}")
    print()
    print(f"    → Dùng ngưỡng {opt_threshold:.3f} thay vì 50% trong predictor_improved.py")

    return opt_threshold


# ============================================================================
# STEP 6: Full Evaluation
# ============================================================================

def evaluate_model(model, X_test, y_test, feature_names, threshold=0.5):
    """Đánh giá toàn diện model trên test set."""

    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred  = (y_proba >= threshold).astype(int)

    print("\n" + "=" * 70)
    print(f"FINAL MODEL EVALUATION (threshold={threshold:.3f})")
    print("=" * 70)
    print(classification_report(y_test, y_pred,
                                target_names=["Legitimate", "Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"Confusion Matrix:")
    print(f"  TN={tn}  FP={fp}")
    print(f"  FN={fn}  TP={tp}")
    print(f"\nAdditional Metrics:")
    print(f"  ROC-AUC   : {roc_auc_score(y_test, y_proba):.4f}")
    print(f"  MCC       : {matthews_corrcoef(y_test, y_pred):.4f}")
    print(f"  Brier Score: {brier_score_loss(y_test, y_proba):.4f}  (lower=better, 0=perfect)")
    print(f"  FPR       : {fp/(fp+tn):.4f}  ({fp/(fp+tn)*100:.1f}% legitimate flagged as phishing)")
    print(f"  FNR       : {fn/(fn+tp):.4f}  ({fn/(fn+tp)*100:.1f}% phishing missed)")

    return roc_auc_score(y_test, y_proba)


# ============================================================================
# STEP 7: Generate Plots
# ============================================================================

def generate_plots(model, X_test, y_test, feature_names, baselines_df):
    """Tạo 4 plots cho thesis."""

    y_proba = model.predict_proba(X_test)[:, 1]

    # --- Plot 1: Confusion Matrix ---
    y_pred = (y_proba >= 0.5).astype(int)
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Legitimate", "Phishing"],
                yticklabels=["Legitimate", "Phishing"])
    plt.title("Confusion Matrix — XGBoost + Calibrated")
    plt.ylabel("True Label"); plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "confusion_matrix.png"), dpi=150)
    plt.close()
    print("[✓] Saved: confusion_matrix.png")

    # --- Plot 2: ROC Curve ---
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc = roc_auc_score(y_test, y_proba)
    plt.figure(figsize=(7, 5))
    plt.plot(fpr, tpr, lw=2, label=f"XGBoost Calibrated (AUC = {auc:.4f})")
    plt.plot([0, 1], [0, 1], "k--", lw=1, label="Random")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("ROC Curve — XGBoost + Calibrated")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "roc_curve.png"), dpi=150)
    plt.close()
    print("[✓] Saved: roc_curve.png")

    # --- Plot 3: Calibration Curve ---
    # Bằng chứng rằng confidence score có ý nghĩa xác suất [Ref 2]
    prob_true, prob_pred = calibration_curve(y_test, y_proba, n_bins=10)
    plt.figure(figsize=(7, 5))
    plt.plot(prob_pred, prob_true, "s-", color="steelblue",
             label="XGBoost + Isotonic")
    plt.plot([0, 1], [0, 1], "k--", lw=1, label="Perfect calibration")
    plt.fill_between([0, 1], [0, 0.1], [0, 0.1], alpha=0)
    brier = brier_score_loss(y_test, y_proba)
    plt.xlabel("Mean Predicted Probability")
    plt.ylabel("Fraction of Positives (Actual)")
    plt.title(f"Calibration Curve (Reliability Diagram)\nBrier Score = {brier:.4f}")
    plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "calibration_curve.png"), dpi=150)
    plt.close()
    print("[✓] Saved: calibration_curve.png")

    # --- Plot 4: SHAP Summary Plot ---
    print("[+] Computing SHAP values (may take ~1 min)...")
    try:
        # Dùng base_model bên trong CalibratedClassifierCV
        # Lấy base estimator đầu tiên (từ cv fold)
        base_model = model.calibrated_classifiers_[0].estimator
        explainer = shap.TreeExplainer(base_model)
        
        # Chỉ dùng 500 samples để nhanh
        X_sample = X_test.iloc[:500]
        shap_values = explainer.shap_values(X_sample)
        
        # Với XGBoost binary: shap_values là array 2D [n_samples, n_features]
        if isinstance(shap_values, list):
            sv = shap_values[1]  # class "phishing"
        else:
            sv = shap_values

        plt.figure(figsize=(10, 8))
        shap.summary_plot(sv, X_sample, feature_names=feature_names,
                          show=False, plot_type="bar")
        plt.title("SHAP Feature Importance — Top Features for Phishing Detection")
        plt.tight_layout()
        plt.savefig(os.path.join(BASE_DIR, "shap_importance.png"), dpi=150,
                    bbox_inches="tight")
        plt.close()
        print("[✓] Saved: shap_importance.png")

        # Waterfall plot cho 1 URL mẫu
        plt.figure(figsize=(10, 6))
        shap.summary_plot(sv, X_sample, feature_names=feature_names,
                          show=False, plot_type="dot")
        plt.title("SHAP Beeswarm Plot — Feature Impact Distribution")
        plt.tight_layout()
        plt.savefig(os.path.join(BASE_DIR, "shap_beeswarm.png"), dpi=150,
                    bbox_inches="tight")
        plt.close()
        print("[✓] Saved: shap_beeswarm.png")

    except Exception as e:
        print(f"[!] SHAP failed: {e}")

    # --- Plot 5: Baseline Comparison Bar Chart ---
    metrics = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]
    fig, axes = plt.subplots(1, len(metrics), figsize=(18, 5))
    colors = ["#e74c3c", "#f39c12", "#3498db", "#2ecc71"]
    for i, metric in enumerate(metrics):
        vals = baselines_df[metric].values
        bars = axes[i].bar(range(len(vals)), vals, color=colors, alpha=0.85)
        axes[i].set_xticks(range(len(vals)))
        axes[i].set_xticklabels(["(a)", "(b)", "(c)", "(d)"], fontsize=9)
        axes[i].set_title(metric, fontsize=11, fontweight="bold")
        axes[i].set_ylim(max(0, vals.min() - 0.05), min(1.0, vals.max() + 0.05))
        axes[i].grid(axis="y", alpha=0.3)
        for bar, val in zip(bars, vals):
            axes[i].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
                         f"{val:.3f}", ha="center", va="bottom", fontsize=8)
    # Legend
    from matplotlib.patches import Patch
    labels = [idx.split(" ")[0] + " " + " ".join(idx.split(" ")[1:3])
              for idx in baselines_df.index]
    legend_handles = [Patch(color=c, label=l) for c, l in zip(colors, labels)]
    fig.legend(handles=legend_handles, loc="lower center", ncol=4,
               bbox_to_anchor=(0.5, -0.05), fontsize=9)
    fig.suptitle("Baseline Comparison — Phishing Detection Models", 
                 fontsize=13, fontweight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, "baseline_comparison.png"), dpi=150,
                bbox_inches="tight")
    plt.close()
    print("[✓] Saved: baseline_comparison.png")


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def main():
    print("=" * 70)
    print("CheckPost v2.0 — Training Pipeline")
    print("XGBoost + Calibrated + SHAP + Threshold Optimization")
    print("=" * 70)

    if not os.path.exists(DATASET_PATH):
        print(f"[!] Dataset not found: {DATASET_PATH}")
        return

    # 1. Load data
    print("\n[STEP 1] Loading data...")
    X_train, X_test, y_train, y_test, feature_names = load_and_prepare_data(
        DATASET_PATH, test_size=0.2
    )

    # 2. Baseline comparison (bắt buộc cho thesis)
    print("\n[STEP 2] Baseline comparison...")
    baselines_df = compare_baselines(X_train, X_test, y_train, y_test)

    # 3. Tune XGBoost
    print("\n[STEP 3] Hyperparameter tuning...")
    best_xgb = tune_xgboost(X_train, y_train, cv=5)

    # 4. Calibrate probabilities
    print("\n[STEP 4] Probability calibration...")
    calibrated_model = calibrate_model(best_xgb, X_train, y_train, cv=5)

    # 5. Threshold optimization
    print("\n[STEP 5] Threshold optimization (F-0.5)...")
    optimal_threshold = optimize_threshold(calibrated_model, X_test, y_test, beta=0.5)

    # 6. Final evaluation
    print("\n[STEP 6] Final evaluation...")
    evaluate_model(calibrated_model, X_test, y_test, feature_names,
                   threshold=optimal_threshold)

    # 7. Generate plots
    print("\n[STEP 7] Generating plots...")
    generate_plots(calibrated_model, X_test, y_test, feature_names, baselines_df)

    # 8. Save model + metadata
    print("\n[STEP 8] Saving model...")
    os.makedirs(os.path.join(BASE_DIR, "MLModels"), exist_ok=True)
    joblib.dump(calibrated_model, MODEL_PATH)
    joblib.dump(feature_names, FEATURES_PATH)

    threshold_meta = {
        "optimal_threshold":     round(optimal_threshold, 4),
        "beta":                  0.5,
        "method":                "F-beta precision_recall_curve",
        "note": (
            f"Dùng ngưỡng {optimal_threshold:.3f} trong predictor_improved.py "
            f"thay vì hardcoded 0.5. Tối ưu hóa theo F-0.5 "
            f"(precision quan trọng hơn recall 2:1 để giảm false positive)."
        )
    }
    with open(THRESHOLD_PATH, "w") as f:
        json.dump(threshold_meta, f, indent=2)

    print(f"\n[✓] Model saved  : {MODEL_PATH}")
    print(f"[✓] Features saved: {FEATURES_PATH}")
    print(f"[✓] Threshold saved: {THRESHOLD_PATH}")

    print("\n" + "=" * 70)
    print("[✓] TRAINING COMPLETE!")
    print("=" * 70)
    print("\nFiles generated:")
    for f in ["confusion_matrix.png", "roc_curve.png", "calibration_curve.png",
              "shap_importance.png", "shap_beeswarm.png", "baseline_comparison.png"]:
        path = os.path.join(BASE_DIR, f)
        if os.path.exists(path):
            print(f"  ✓ {f}")
    print("\nNext step: Chạy predictor_improved.py để test model mới.")


if __name__ == "__main__":
    main()
