# check_model_status.py
"""
Kiểm tra trạng thái model hiện tại
- File tồn tại?
- Model performance?
- Dataset đủ lớn?
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score

BACKEND_DIR = os.path.dirname(__file__)
MODEL_TUNED = os.path.join(BACKEND_DIR, "MLModels", "phishing_rf_model_tuned.pkl")
MODEL_DEFAULT = os.path.join(BACKEND_DIR, "MLModels", "phishing_rf_model.pkl")
FEATURES_TUNED = os.path.join(BACKEND_DIR, "MLModels", "phishing_rf_model_tuned_features.pkl")
FEATURES_DEFAULT = os.path.join(BACKEND_DIR, "MLModels", "phishing_rf_model_features.pkl")
DATASET = os.path.join(BACKEND_DIR, "Datasets", "dataset.csv")

print("="*70)
print("MODEL STATUS CHECK")
print("="*70)

# 1. Check model files
print("\n[1] MODEL FILES:")
print(f"    Tuned model exists: {os.path.exists(MODEL_TUNED)}")
print(f"    Default model exists: {os.path.exists(MODEL_DEFAULT)}")
print(f"    Tuned features exists: {os.path.exists(FEATURES_TUNED)}")

# 2. Check dataset
print(f"\n[2] DATASET:")
print(f"    Dataset exists: {os.path.exists(DATASET)}")

if os.path.exists(DATASET):
    df = pd.read_csv(DATASET)
    print(f"    Dataset shape: {df.shape}")
    print(f"    Columns: {df.columns.tolist()}")
    
    # Check label distribution
    if 'label' in df.columns:
        label_dist = df['label'].value_counts()
        print(f"    Label distribution:\n{label_dist}")
        print(f"    Imbalance ratio: {label_dist.max() / label_dist.min():.2f}x")
    else:
        print(f"    ⚠️  No 'label' column found!")
else:
    print(f"    ❌ Dataset NOT found at {DATASET}")
    print(f"    → Model cannot be trained without data!")

# 3. Load and check model
print(f"\n[3] MODEL PERFORMANCE:")

model_to_check = None
model_path = None

if os.path.exists(MODEL_TUNED):
    print(f"    Loading TUNED model...")
    model_to_check = joblib.load(MODEL_TUNED)
    model_path = MODEL_TUNED
    features_path = FEATURES_TUNED
elif os.path.exists(MODEL_DEFAULT):
    print(f"    Loading DEFAULT model...")
    model_to_check = joblib.load(MODEL_DEFAULT)
    model_path = MODEL_DEFAULT
    features_path = None
else:
    print(f"    ❌ No model file found!")

if model_to_check is not None:
    print(f"    Model type: {type(model_to_check).__name__}")
    print(f"    Number of features: {model_to_check.n_features_in_}")
    
    if hasattr(model_to_check, 'feature_names_in_'):
        features = model_to_check.feature_names_in_.tolist()
        print(f"    Feature names: {features[:5]}... (showing first 5)")
    
    # Try to get feature importance
    if hasattr(model_to_check, 'feature_importances_'):
        importance = model_to_check.feature_importances_
        top_5_idx = np.argsort(importance)[-5:][::-1]
        if hasattr(model_to_check, 'feature_names_in_'):
            top_features = model_to_check.feature_names_in_[top_5_idx]
            print(f"    Top 5 important features:")
            for feat, imp in zip(top_features, importance[top_5_idx]):
                print(f"        - {feat}: {imp:.4f}")

# 4. Test on sample URLs
print(f"\n[4] TEST ON SAMPLE URLs:")

if model_to_check is not None:
    try:
        from predictor_improved import extract_features_async, get_risk_report
        import asyncio
        
        async def test_urls():
            test_urls = [
                "https://www.google.com",
                "https://www.youtube.com",
                "https://www.facebook.com",
            ]
            
            for url in test_urls:
                try:
                    features = await extract_features_async(url)
                    report = get_risk_report(url, features)
                    print(f"    {url}: {report['model_prediction']} (score: {report['risk_score']}%)")
                except Exception as e:
                    print(f"    {url}: Error - {type(e).__name__}")
        
        # asyncio.run(test_urls())
        print("    (Skipped - would require network calls)")
    except:
        pass

# 5. Recommendations
print(f"\n[5] RECOMMENDATIONS:")

issues = []

if not os.path.exists(DATASET):
    issues.append("Dataset not found - need to create Datasets/dataset.csv with phishing URLs")

if os.path.exists(DATASET):
    df = pd.read_csv(DATASET)
    if len(df) < 500:
        issues.append(f"Dataset too small ({len(df)} samples) - need at least 500")
    
    if 'label' in df.columns:
        label_counts = df['label'].value_counts()
        if label_counts.max() / label_counts.min() > 3:
            issues.append(f"Class imbalance too high ({label_counts.max() / label_counts.min():.1f}x) - need more phishing samples")

if not os.path.exists(MODEL_TUNED):
    issues.append("No tuned model - run 'python train_model.py' to train with fine-tuning")

if not issues:
    print("    ✅ Everything looks good! Model should be working.")
else:
    print("    ❌ Issues found:")
    for i, issue in enumerate(issues, 1):
        print(f"        {i}. {issue}")

print("\n" + "="*70)
print("NEXT STEPS:")
print("="*70)
print("""
If model is not performing well:

1. CHECK DATASET:
   $ python check_model_status.py
   
2. PREPARE DATA:
   - Collect phishing & legitimate URLs
   - Create Datasets/dataset.csv with 'url' and 'label' columns
   - Minimum 500 samples (250 phishing + 250 legitimate)

3. TRAIN MODEL:
   $ python train_model.py
   
4. EVALUATE:
   - Check confusion_matrix.png
   - Check roc_curve.png
   - Check feature_importance.png
   
5. OPTIMIZE THRESHOLD:
   $ python threshold_optimization.py

6. TEST:
   $ python predictor_improved.py
""")
