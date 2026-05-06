# train_model.py
"""
Fine-tuning mô hình phát hiện phishing với best practices ML
- Cross-validation
- Hyperparameter tuning
- Class imbalance handling
- Feature importance analysis
- Comprehensive metrics evaluation
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    GridSearchCV,
    cross_val_score,
    cross_validate
)
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    f1_score,
    precision_score,
    recall_score,
    matthews_corrcoef
)
from sklearn.utils.class_weight import compute_class_weight
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from imblearn.over_sampling import SMOTE

# ============================================================================
# 1. LOAD & PREPARE DATA
# ============================================================================

def load_and_prepare_data(csv_path, target_col='Result', test_size=0.2, random_state=42):
    """Load dữ liệu và chuẩn bị train/test split"""
    
    df = pd.read_csv(csv_path)
    print(f"[+] Dữ liệu loaded: {df.shape[0]} samples, {df.shape[1]} features")
    
    # Kiểm tra missing values
    missing = df.isnull().sum()
    if missing.any():
        print("[!] Missing values detected:")
        print(missing[missing > 0])
        # Xử lý missing values (tùy thuộc vào loại features)
        df = df.fillna(df.median(numeric_only=True))
    
    # Kiểm tra class distribution
    print(f"\n[+] Class distribution:")
    class_dist = df[target_col].value_counts().sort_index()
    print(class_dist)
    if len(class_dist) == 2:
        ratio = class_dist.iloc[1] / class_dist.iloc[0]
        print(f"    - Imbalance ratio: {ratio:.2f}")
    
    # Tách features và target
    X = df.drop(columns=[target_col])
    y = df[target_col]
    
    # Train-test split (stratified để giữ class distribution)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y  # ⭐ QUAN TRỌNG: Giữ tỷ lệ class như nhau
    )
    
    print(f"\n[+] Train set: {X_train.shape[0]} samples")
    print(f"[+] Test set: {X_test.shape[0]} samples")
    
    return X_train, X_test, y_train, y_test, X.columns.tolist()

# ============================================================================
# 2. HANDLE CLASS IMBALANCE với SMOTE
# ============================================================================

def apply_smote(X_train, y_train, random_state=42):
    """SMOTE: Synthetic Minority Over-sampling Technique"""
    smote = SMOTE(random_state=random_state, k_neighbors=5)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    
    print(f"\n[+] SMOTE applied:")
    print(f"    - Before: {X_train.shape[0]} samples")
    print(f"    - After: {X_train_resampled.shape[0]} samples")
    # Use unique instead of bincount to handle any integer values
    unique_labels, counts = np.unique(y_train_resampled, return_counts=True)
    dist_dict = dict(zip(unique_labels, counts))
    print(f"    - New class distribution: {dist_dict}")
    
    return X_train_resampled, y_train_resampled

# ============================================================================
# 3. HYPERPARAMETER TUNING với GridSearchCV
# ============================================================================

def hyperparameter_tuning(X_train, y_train, cv=5):
    """
    Tìm best hyperparameters cho Random Forest
    ⭐ KHI CHẠY LẦN ĐẦU CÓ THỂ MẤT 10-30 PHÚT
    """
    
    # Định nghĩa parameter grid
    param_grid = {
        'n_estimators': [100, 200, 300],  # Số lượng tree
        'max_depth': [10, 20, 30, None],  # Độ sâu tree
        'min_samples_split': [2, 5, 10],  # Min samples để split
        'min_samples_leaf': [1, 2, 4],    # Min samples ở leaf
        'max_features': ['sqrt', 'log2'], # Feature selection
        'class_weight': ['balanced', 'balanced_subsample']  # Xử lý imbalance
    }
    
    print("\n[+] Bắt đầu GridSearchCV (có thể mất vài phút)...")
    
    rf = RandomForestClassifier(random_state=42, n_jobs=-1)
    
    grid_search = GridSearchCV(
        rf,
        param_grid,
        cv=cv,  # Stratified k-fold
        scoring='f1_weighted',  # F1-score cân nhắc class imbalance
        n_jobs=-1,
        verbose=2
    )
    
    grid_search.fit(X_train, y_train)
    
    print(f"\n[✓] Best parameters: {grid_search.best_params_}")
    print(f"[✓] Best CV score (F1-weighted): {grid_search.best_score_:.4f}")
    
    return grid_search.best_estimator_

# ============================================================================
# 4. CROSS-VALIDATION & EVALUATION
# ============================================================================

def evaluate_model(model, X_train, X_test, y_train, y_test, feature_names, cv=5):
    """Đánh giá model một cách toàn diện"""
    
    print("\n" + "="*60)
    print("CROSS-VALIDATION METRICS (5-Fold Stratified)")
    print("="*60)
    
    # Cross-validation trên training set
    scoring = {
        'f1_weighted': 'f1_weighted',
        'precision': 'precision_weighted',
        'recall': 'recall_weighted',
        'roc_auc': 'roc_auc'
    }
    
    cv_results = cross_validate(
        model, X_train, y_train,
        cv=StratifiedKFold(n_splits=cv, shuffle=True, random_state=42),
        scoring=scoring,
        return_train_score=True
    )
    
    for metric in scoring.keys():
        train_scores = cv_results[f'train_{metric}']
        test_scores = cv_results[f'test_{metric}']
        
        print(f"\n{metric.upper()}:")
        print(f"  Train: {train_scores.mean():.4f} (+/- {train_scores.std():.4f})")
        print(f"  Test:  {test_scores.mean():.4f} (+/- {test_scores.std():.4f})")
    
    # TEST SET EVALUATION
    print("\n" + "="*60)
    print("TEST SET DETAILED METRICS")
    print("="*60)
    
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n[+] Confusion Matrix:")
    print(cm)
    tn, fp, fn, tp = cm.ravel()
    print(f"    - True Negatives (TN): {tn}")
    print(f"    - False Positives (FP): {fp}")
    print(f"    - False Negatives (FN): {fn}")
    print(f"    - True Positives (TP): {tp}")
    
    # Thêm metrics
    print(f"\n[+] Additional Metrics:")
    print(f"    - ROC-AUC: {roc_auc_score(y_test, y_pred_proba):.4f}")
    print(f"    - Matthews Corr Coef: {matthews_corrcoef(y_test, y_pred):.4f}")
    print(f"    - Specificity (TNR): {tn/(tn+fp):.4f}")
    print(f"    - Sensitivity (TPR): {tp/(tp+fn):.4f}")
    print(f"    - False Positive Rate: {fp/(fp+tn):.4f}")
    print(f"    - False Negative Rate: {fn/(fn+tp):.4f}")
    
    # FEATURE IMPORTANCE
    print("\n" + "="*60)
    print("TOP 15 MOST IMPORTANT FEATURES")
    print("="*60)
    
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(feature_importance.head(15).to_string(index=False))
    
    # Visualize confusion matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    plt.title('Confusion Matrix - Test Set')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(os.path.dirname(__file__), 'confusion_matrix.png'))
    print("\n[✓] Confusion matrix saved to confusion_matrix.png")
    
    # ROC Curve
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f'ROC-AUC = {roc_auc_score(y_test, y_pred_proba):.4f}')
    plt.plot([0, 1], [0, 1], 'k--', label='Random')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve - Test Set')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(os.path.dirname(__file__), 'roc_curve.png'))
    print("[✓] ROC curve saved to roc_curve.png")
    
    # Feature Importance Plot
    plt.figure(figsize=(10, 8))
    top_features = feature_importance.head(15)
    plt.barh(range(len(top_features)), top_features['importance'])
    plt.yticks(range(len(top_features)), top_features['feature'])
    plt.xlabel('Importance Score')
    plt.title('Top 15 Feature Importance')
    plt.tight_layout()
    plt.savefig(os.path.join(os.path.dirname(__file__), 'feature_importance.png'))
    print("[✓] Feature importance plot saved to feature_importance.png")
    
    return cv_results

# ============================================================================
# 5. SAVE MODEL & FEATURE NAMES
# ============================================================================

def save_trained_model(model, feature_names, model_path):
    """Lưu model và feature names"""
    joblib.dump(model, model_path)
    print(f"\n[✓] Model saved to {model_path}")
    
    # Lưu feature names (cần thiết cho prediction)
    feature_path = model_path.replace('.pkl', '_features.pkl')
    joblib.dump(feature_names, feature_path)
    print(f"[✓] Feature names saved to {feature_path}")

# ============================================================================
# 6. MAIN TRAINING PIPELINE
# ============================================================================

def main():
    """Complete training pipeline"""
    
    # Paths
    dataset_path = os.path.join(os.path.dirname(__file__), 'Datasets', 'dataset.csv')
    model_path = os.path.join(os.path.dirname(__file__), 'MLModels', 'phishing_rf_model_tuned.pkl')
    
    if not os.path.exists(dataset_path):
        print(f"[!] Dataset not found: {dataset_path}")
        print("    Vui lòng chuẩn bị file dataset.csv")
        return
    
    # STEP 1: Load dữ liệu
    print("[STEP 1] Loading and preparing data...")
    X_train, X_test, y_train, y_test, feature_names = load_and_prepare_data(
        dataset_path,
        target_col='Result',  # Thay đổi nếu tên cột khác
        test_size=0.2
    )
    
    # STEP 2: Xử lý class imbalance
    print("\n[STEP 2] Handling class imbalance with SMOTE...")
    X_train_balanced, y_train_balanced = apply_smote(X_train, y_train)
    
    # STEP 3: Hyperparameter tuning
    print("\n[STEP 3] Hyperparameter tuning (GridSearchCV)...")
    best_model = hyperparameter_tuning(X_train_balanced, y_train_balanced, cv=5)
    
    # STEP 4: Đánh giá model
    print("\n[STEP 4] Evaluating model...")
    evaluate_model(best_model, X_train_balanced, X_test, y_train_balanced, y_test, feature_names, cv=5)
    
    # STEP 5: Lưu model
    print("\n[STEP 5] Saving trained model...")
    save_trained_model(best_model, feature_names, model_path)
    
    print("\n" + "="*60)
    print("[✓] TRAINING COMPLETE!")
    print("="*60)
    print("\nNotes:")
    print("1. Sử dụng file 'phishing_rf_model_tuned.pkl' cho predictions")
    print("2. Review confusion_matrix.png, roc_curve.png, feature_importance.png")
    print("3. Nếu F1-score < 0.85, cố gắng:")
    print("   - Thêm dữ liệu training")
    print("   - Cải thiện feature engineering")
    print("   - Thay đổi class_weight balance strategy")

if __name__ == "__main__":
    main()
