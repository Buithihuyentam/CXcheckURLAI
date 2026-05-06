# QUICK START - Fine-tuning Phishing Detection Model

## 📦 Tạo 4 Files Mới

```
backend/
├── train_model.py              ← Fine-tuning with cross-validation
├── predictor_improved.py       ← Improved predictor with proper scoring
├── threshold_optimization.py   ← Find optimal decision threshold
├── FINE_TUNING_GUIDE.md        ← Comprehensive guide (read this!)
└── requirements_updated.txt    ← New dependencies
```

---

## 🎯 3 Bước Chính

### BƯỚC 1: Chuẩn bị Dependencies (2 phút)

```bash
cd backend
pip install imbalanced-learn matplotlib seaborn
# Hoặc:
pip install -r requirements_updated.txt
```

### BƯỚC 2: Fine-tune Model (20-30 phút lần đầu)

```bash
python train_model.py
```

**Output:**

```
✓ Best parameters: {n_estimators: 200, max_depth: 20, ...}
✓ Best CV score (F1-weighted): 0.8234

CROSS-VALIDATION METRICS:
  F1 Score: 0.8234 (+/- 0.0145)
  Precision: 0.8567 (+/- 0.0189)
  Recall: 0.7923 (+/- 0.0201)
  ROC-AUC: 0.9012 (+/- 0.0078)

[✓] confusion_matrix.png
[✓] roc_curve.png
[✓] feature_importance.png
```

**Kiểm tra:**

- F1-score ≥ 0.85? ✅ Good
- F1-score < 0.80? ❌ Cần thêm dữ liệu hoặc features

### BƯỚC 3: Optimize Threshold (5 phút)

```bash
python threshold_optimization.py
```

**Output:**

```
STRATEGY 1 - F1-Score Optimization
  → Optimal threshold: 0.45
  → Best F1-score: 0.8234

STRATEGY 2 - Business-Focused (Max 5% false alarms, Min 90% detection)
  → Optimal threshold: 0.38
  → FPR: 0.045 | Recall: 0.921

[✓] threshold_analysis.png
```

---

## 📊 Sau khi Fine-tune

### Cập nhật app.py

```python
# app.py

# ❌ OLD
from predictor import extract_features_async, get_risk_report

# ✅ NEW
from predictor_improved import extract_features_async, get_risk_report
```

### Cập nhật confidence scoring

```python
# predictor_improved.py - Line 250-270

# OLD (arbitrary penalty):
score = confidence if prediction == 1 else (100 - confidence)

# NEW (probability-based):
report = {
    "risk_score": round(risk_score, 2),
    "confidence": round(confidence, 2),
    "phishing_probability": round(proba[1] * 100, 2),
    "legitimate_probability": round(proba[0] * 100, 2),
}
```

---

## 🔍 Hiểu Output

### Metrics Visualization

**Confusion Matrix:**

```
              Predicted
             Legit  Phish
Actual  L  [ TN ]  [ FP ]  ← False Positives (URL bình thường cảnh báo)
        P  [ FN ]  [ TP ]  ← False Negatives (Phishing không bị phát hiện)
```

**ROC Curve:**

- X: False Positive Rate (1 - Specificity)
- Y: True Positive Rate (Sensitivity/Recall)
- 🟢 AUC = 0.90+ → Excellent
- 🟡 AUC = 0.80-0.90 → Good
- 🔴 AUC < 0.80 → Needs improvement

**Feature Importance:**

```
feature_name          importance
SSL_final_state       0.124
Domain_age            0.089
URL_of_Anchor         0.078
...
```

---

## ❓ Troubleshooting

### Problem: F1-score < 0.80

**Solution 1: Thêm dữ liệu**

```
Phishing detection cần minimum 500+ samples (250 legit + 250 phishing)
Lý tưởng: 5000+ samples
```

**Solution 2: Improve features**

```python
# Add in extract_features_async():
def extract_features_async(url):
    # ... existing code ...

    # NEW FEATURES
    features['url_entropy'] = calculate_entropy(url)
    features['domain_age_days'] = (now - creation_date).days
    features['domain_life_remaining'] = (expiration_date - now).days
    features['is_free_tld'] = -1 if domain.endswith('.tk') else 1
```

**Solution 3: Adjust class weights**

```python
# train_model.py

rf = RandomForestClassifier(
    class_weight='balanced_subsample',  # Xử lý imbalance
    n_estimators=300,  # Tăng lên
    max_depth=25,
)
```

---

### Problem: Too many false positives (cảnh báo nhiều)

**Solution 1: Tăng decision threshold**

```python
# predictor_improved.py - get_risk_report()

# ❌ OLD
if risk_score >= 60:
    level = "WARNING"

# ✅ NEW (ngặt hơn)
if risk_score >= 75:
    level = "WARNING"
```

**Solution 2: Optimize threshold từ data**

```bash
python threshold_optimization.py
# Chọn threshold có high precision (low false positives)
```

---

### Problem: Too many false negatives (bỏ sót phishing)

**Solution: Giảm decision threshold**

```python
# predictor_improved.py

# ❌ OLD
if risk_score >= 60:
    level = "WARNING"

# ✅ NEW (nhạy hơn)
if risk_score >= 40:
    level = "WARNING"
```

---

## 📈 Performance Interpretation

```
EXCELLENT ✅         ACCEPTABLE ⚠️           POOR ❌
────────────────────────────────────────────────────
F1 ≥ 0.85           0.75 ≤ F1 < 0.85        F1 < 0.75
AUC ≥ 0.90          0.80 ≤ AUC < 0.90       AUC < 0.80
Precision ≥ 0.85    0.75 ≤ P < 0.85         P < 0.75
Recall ≥ 0.82       0.70 ≤ R < 0.82         R < 0.70
```

---

## 🚀 Production Deployment

### Step 1: Validate model

```bash
# Check if tuned model is better
Compare:
  - F1-score: old vs new
  - AUC: old vs new
  - False positive rate: old vs new
```

### Step 2: Update predictor

```python
# Update app.py to use predictor_improved.py
# Or rename files:
mv MLModels/phishing_rf_model.pkl MLModels/phishing_rf_model_old.pkl
cp MLModels/phishing_rf_model_tuned.pkl MLModels/phishing_rf_model.pkl
```

### Step 3: Monitor performance

```python
def log_prediction(url, prediction, user_corrected=None):
    """Log for periodic retraining"""
    import json

    record = {
        'timestamp': datetime.now().isoformat(),
        'url': url,
        'prediction': prediction,
        'user_feedback': user_corrected,  # True if user corrected
    }

    with open('prediction_logs.jsonl', 'a') as f:
        f.write(json.dumps(record) + '\n')

# Retrain weekly
# python train_model.py  # Tự động dùng data mới
```

---

## 🎓 Key Concepts

| Concept                    | Definition                          | Why it matters                 |
| -------------------------- | ----------------------------------- | ------------------------------ |
| **Cross-validation**       | Test model trên multiple folds      | Avoid overfitting              |
| **SMOTE**                  | Generate synthetic phishing samples | Handle class imbalance         |
| **Hyperparameter tuning**  | Find best RF parameters             | Improve accuracy               |
| **F1-score**               | Balance precision & recall          | Real-world metric              |
| **ROC-AUC**                | Ranking ability of model            | Model discrimination           |
| **Threshold optimization** | Find best decision boundary         | Tune precision-recall tradeoff |

---

## 📝 Next Steps

1. ✅ Run `python train_model.py` (20-30 min)
2. ✅ Review confusion_matrix.png, roc_curve.png
3. ✅ Run `python threshold_optimization.py` (5 min)
4. ✅ Update `app.py` to use `predictor_improved.py`
5. ✅ Test with real URLs
6. ⏰ Setup weekly retraining (new data → new model)
7. 📊 Monitor metrics on production

---

## 💡 Best Practices Summary

```python
# DO ✅
- Use stratified k-fold cross-validation
- Handle class imbalance (SMOTE + class_weight)
- Tune hyperparameters (GridSearchCV)
- Use F1-score as main metric
- Monitor model on production
- Retrain periodically with new data

# DON'T ❌
- Use accuracy on imbalanced data
- Train on full dataset (no validation split)
- Hardcode thresholds without data analysis
- Use default hyperparameters
- Ignore false positive/negative tradeoff
- Never retrain (concept drift)
```

---

## 📞 Support

- **Metrics explanation**: See FINE_TUNING_GUIDE.md
- **Feature engineering**: See predictor_improved.py docstrings
- **Threshold strategy**: Run threshold_optimization.py
- **Debugging**: Check FINE_TUNING_GUIDE.md "Debugging Checklist"
