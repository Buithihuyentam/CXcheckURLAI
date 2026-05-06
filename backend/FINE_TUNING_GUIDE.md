# FINE-TUNING GUIDE - Phishing Detection Model

## 📋 Tóm tắt vấn đề hiện tại

| Vấn đề                              | Giải pháp                                                          |
| ----------------------------------- | ------------------------------------------------------------------ |
| ❌ Threshold tùy ý (54, 75, 0.5...) | ✅ Tính từ dữ liệu: `df['url_length'].quantile([0.25, 0.5, 0.75])` |
| ❌ Penalty hardcoded (score - 25)   | ✅ Dùng model probability thực tế                                  |
| ❌ Không cross-validation           | ✅ StratifiedKFold 5-fold                                          |
| ❌ Không hyperparameter tuning      | ✅ GridSearchCV tự động tìm best params                            |
| ❌ Không xử lý imbalance            | ✅ SMOTE resampling + class_weight balanced                        |
| ❌ Không metrics                    | ✅ F1, Precision, Recall, ROC-AUC, Matthews Corr Coef              |

---

## 🚀 Quy trình Fine-tuning

### BƯỚC 1: Chuẩn bị dữ liệu

```bash
# Kiểm tra dataset
cd backend
python
>>> import pandas as pd
>>> df = pd.read_csv('Datasets/dataset.csv')
>>> df.shape
>>> df.isnull().sum()
>>> df['label'].value_counts()  # Kiểm tra class distribution
>>> df.describe()
```

**Những điều cần kiểm tra:**

- Có missing values không?
- Class distribution như thế nào? (Imbalance ratio)
- Features có scale lớn khác nhau không?

---

### BƯỚC 2: Chạy Fine-tuning (Lần đầu: ~20-30 phút)

```bash
cd backend
python train_model.py
```

**Kết quả tạo ra:**

- ✅ `MLModels/phishing_rf_model_tuned.pkl` - Model tối ưu
- ✅ `MLModels/phishing_rf_model_tuned_features.pkl` - Feature names
- 📊 `confusion_matrix.png` - Confusion matrix visualization
- 📊 `roc_curve.png` - ROC curve với AUC score
- 📊 `feature_importance.png` - Top 15 features

**Đọc output:**

```
✓ Best parameters: {...}
✓ Best CV score (F1-weighted): 0.8234

CROSS-VALIDATION METRICS:
  - F1 Score: 0.8234 (+/- 0.0145)
  - Precision: 0.8567 (+/- 0.0189)
  - Recall: 0.7923 (+/- 0.0201)
  - ROC-AUC: 0.9012 (+/- 0.0078)
```

**Giải thích:**

- **F1-score** (chính): Cân bằng Precision và Recall
- **Precision**: Trong số được dự đoán là phishing, % đúng
- **Recall**: Trong số phishing thực tế, % bị phát hiện
- **ROC-AUC**: Khả năng phân biệt (1.0 = perfect, 0.5 = random)

---

### BƯỚC 3: Đánh giá chi tiết kết quả

**Kiểm tra Confusion Matrix:**

```
           Predicted
          Legit  Phish
Actual  L  [TN]   [FP]    <- False Positives: URL bình thường bị cảnh báo
        P  [FN]   [TP]    <- False Negatives: Phishing không bị phát hiện
```

**Metrics quan trọng:**

```
Specificity (TNR) = TN/(TN+FP)      <- Tỷ lệ phát hiện đúng legitimate URLs
Sensitivity (TPR) = TP/(TP+FN)      <- Tỷ lệ phát hiện đúng phishing URLs
False Positive Rate = FP/(FP+TN)     <- Tỷ lệ false alarm (nên < 5%)
```

---

### BƯỚC 4: Nếu kết quả không tốt (F1 < 0.85)

#### Trường hợp 1: Recall thấp (bỏ sót phishing)

```python
# Giảm decision threshold (detect phishing dễ hơn)
# Trong get_risk_report, thay đổi:
if risk_score >= 40:  # Thay từ 60 xuống 40
    level = "WARNING"
```

#### Trường hợp 2: False Positive cao (cảnh báo nhiều)

```python
# Tăng decision threshold (ngặt hơn)
if risk_score >= 75:  # Thay từ 60 lên 75
    level = "WARNING"
```

#### Trường hợp 3: Model không tốt

- **Thêm dữ liệu**: Phishing detection cần minimum 1000+ samples
- **Feature engineering**:
  ```python
  # Thêm features mới
  features['domain_registration_days'] = age_days  # Số ngày từ ngày tạo
  features['domain_expiration_days'] = remaining_days  # Số ngày còn lại
  features['url_entropy'] = calculate_entropy(url)  # Độ random của URL
  ```
- **Feature selection**: Xóa features không quan trọng:
  ```python
  # Dựa vào feature_importance.png, giữ lại top 20 features
  important_features = top_20_features
  X_train = X_train[important_features]
  ```

---

## 📊 Hiểu kết quả

### Scenario 1: Model tốt ✅

```
F1-score ≈ 0.85+
Precision ≈ 0.85+
Recall ≈ 0.82+
ROC-AUC ≈ 0.90+

→ Sẵn sàng deploy
```

### Scenario 2: Precision tốt, Recall thấp ⚠️

```
Precision = 0.95 (ít false positives)
Recall = 0.65 (bỏ sót nhiều phishing)

→ Conservative model (ít cảnh báo nhưng có thể bỏ sót)
→ Thích hợp cho security-first applications
```

### Scenario 3: Recall tốt, Precision thấp ⚠️

```
Precision = 0.70 (nhiều false positives)
Recall = 0.92 (phát hiện tốt phishing)

→ Aggressive model (nhiều cảnh báo)
→ Thích hợp cho sensitive data protection
```

---

## 🔬 Feature Engineering Tips

### 1. Thêm features tính toán từ WHOIS

```python
def extract_features_async(url):
    # ... existing code ...

    # NEW FEATURES
    age_days = (now - creation_date).days
    remaining_days = (expiration_date - now).days

    features['domain_age_months'] = age_days / 30
    features['domain_life_months'] = (remaining_days + age_days) / 30
    features['is_new_domain'] = 1 if age_days < 30 else -1
    features['is_about_to_expire'] = 1 if remaining_days < 90 else -1

    # Phishing domains often have very short expiration
    if remaining_days < 180:
        features['short_expiration'] = -1
    else:
        features['short_expiration'] = 1
```

### 2. URL Entropy (độ ngẫu nhiên)

```python
import math

def calculate_entropy(text):
    """Entropy cao = URL ngẫu nhiên = có thể phishing"""
    if not text:
        return 0

    entropy = 0
    for char in set(text):
        p = text.count(char) / len(text)
        entropy -= p * math.log2(p)

    return entropy

# Phishing URLs thường có entropy cao
entropy = calculate_entropy(url)
features['url_entropy'] = -1 if entropy > 4.5 else 1
```

### 3. TLD (Top-Level Domain) analysis

```python
def is_suspicious_tld(domain):
    """Some TLDs are more common in phishing"""
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']  # Free domains
    return any(domain.endswith(tld) for tld in suspicious_tlds)

features['suspicious_tld'] = -1 if is_suspicious_tld(domain) else 1
```

### 4. Domain similarity (typosquatting)

```python
from difflib import SequenceMatcher

def domain_similarity_to_known(domain, known_domains):
    """Detect domain typosquatting
    E.g., gooogle.com vs google.com
    """
    max_similarity = max(
        SequenceMatcher(None, domain, known).ratio()
        for known in known_domains
    )

    # High similarity to known domain but not exact = suspicious
    if 0.8 <= max_similarity < 1.0:
        return -1  # Likely typosquatting
    else:
        return 1
```

---

## 🎯 Best Practices

### 1. Luôn dùng Stratified Split

```python
# ✅ GOOD: Giữ class ratio
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# ❌ BAD: Có thể bị imbalance
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2
)
```

### 2. Xử lý Class Imbalance

```python
# Option 1: SMOTE (Synthetic Minority Over-sampling)
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)

# Option 2: Class weights trong model
model = RandomForestClassifier(
    class_weight='balanced',  # Auto-adjust weights
    n_estimators=200,
    random_state=42
)

# Option 3: Combine both
model = RandomForestClassifier(
    class_weight='balanced_subsample',
    n_estimators=200
)
```

### 3. Monitoring Production

```python
# Lưu predictions + actual labels từ users
def log_prediction(url, prediction, user_feedback=None):
    log = {
        'timestamp': datetime.now(),
        'url': url,
        'prediction': prediction,
        'user_feedback': user_feedback,  # True/False nếu user xác nhận
    }

    # Write to database hoặc file
    # Định kỳ (hàng tuần) retrain model với dữ liệu mới
```

### 4. Regular Retraining

```
Schedule: Hàng tuần (hoặc khi có 500+ new samples)
1. Collect user feedback từ production
2. Add positive/negative samples vào training data
3. Chạy train_model.py lại
4. Compare metrics với model cũ
5. Deploy nếu tốt hơn
```

---

## 🔧 Thay đổi code để dùng tuned model

**File: app.py**

```python
# ❌ OLD
from backend.predictor import extract_features_async, get_risk_report

# ✅ NEW
from backend.predictor_improved import extract_features_async, get_risk_report
```

**File: predictor_improved.py** - Lần đầu chạy:

```python
# Script sẽ fallback nếu model tuned không tìm thấy
try:
    model = joblib.load(MODEL_PATH)  # phishing_rf_model_tuned.pkl
except:
    model = joblib.load(MODEL_PATH.replace('_tuned', ''))  # fallback
```

---

## 📈 Tuning Strategies (từ cơ bản đến nâng cao)

### Level 1: Basic (1-2 giờ)

```
- Chạy train_model.py với default params
- Kiểm tra F1-score
- Nếu < 0.80, tăng n_estimators lên 300
```

### Level 2: Intermediate (2-4 giờ)

```
- Fine-tune SMOTE parameters
- Thử different feature selection
- Adjust class_weight balance
```

### Level 3: Advanced (4-8 giờ)

```
- Ensemble models (RandomForest + XGBoost + LightGBM)
- Stacking + Voting classifiers
- Threshold optimization (F1-score threshold)
- SHAP values để explain predictions
```

### Level 4: Production (8+ giờ)

```
- A/B testing old vs new model
- Continuous learning pipeline
- Model monitoring + alerting
- Feature store management
```

---

## 📝 Debugging Checklist

Nếu model performance không tốt:

- [ ] Dataset có đủ samples (minimum 1000)
- [ ] Class distribution balance (ideally ~50:50)
- [ ] Feature có variance (không bị constant)
- [ ] Target label đúng (0/1 không bị reversed)
- [ ] Cross-validation được dùng (không train/test leakage)
- [ ] Hyperparameters được tuned (không dùng default)
- [ ] Class imbalance được xử lý (SMOTE hoặc class_weight)
- [ ] Metrics được tính đúng (F1, không accuracy)
- [ ] Test set không được nhìn trước khi training

---

## 🎓 Tài liệu tham khảo

1. **Scikit-learn Cross-validation**: https://scikit-learn.org/stable/modules/cross_validation.html
2. **Imbalanced Learning**: https://imbalanced-learn.org/stable/
3. **Model Evaluation**: https://scikit-learn.org/stable/modules/model_evaluation.html
4. **Feature Engineering**: https://www.featuretools.com/
5. **Hyperparameter Tuning**: https://optuna.org/

---

## ❓ FAQ

**Q: Cần bao nhiêu dữ liệu để train?**
A: Tối thiểu 500 samples (250 legitimate + 250 phishing), tốt nhất 5000+

**Q: Thường xuyên retrain bao lâu một lần?**
A: Hàng tuần (nếu có user feedback) hoặc hàng tháng (định kỳ)

**Q: Nên tối ưu metric nào?**
A: F1-score (cân bằng Precision-Recall), hoặc precision nếu muốn ít false positives

**Q: Làm sao để explain prediction?**
A: Dùng SHAP hoặc feature importance như trong train_model.py

**Q: Model trên production bị drift như thế nào?**
A: Phishing tactics thay đổi → accuracy giảm → cần retrain định kỳ
