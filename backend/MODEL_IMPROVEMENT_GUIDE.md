# MODEL ACCURACY IMPROVEMENT GUIDE

## 🔍 Vấn đề hiện tại

Model hiện tại không phân biệt được phishing vs legitimate URLs. Ngay cả `youtube.com` cũng được flag là phishing.

**Nguyên nhân chính:**

1. **Model không được train** - Chỉ dùng default model (chưa fine-tuned)
2. **Dataset không tồn tại** hoặc **quá nhỏ** - Model không có dữ liệu để học
3. **Features không đủ** - Chỉ có basic URL features, thiếu page content analysis

---

## 🚀 Giải pháp (3 bước)

### BƯỚC 1: Kiểm tra trạng thái hiện tại

```bash
cd backend
python check_model_status.py
```

**Kiểm tra những gì:**

- ✅ Model file tồn tại?
- ✅ Dataset tồn tại?
- ✅ Dataset size bao nhiêu?
- ✅ Model performance?

**Output mong đợi:**

```
Dataset shape: (500, 2)
Label distribution:
  0    250  # Legitimate
  1    250  # Phishing
Model type: RandomForestClassifier
Top 5 important features: [...]
```

---

### BƯỚC 2A: Nếu KHÔNG có dataset → Tạo test dataset

```bash
python generate_test_dataset.py
```

**Output:**

```
Dataset created:
  Total samples: 400
  Legitimate (0): 200
  Phishing (1): 200

✅ Dataset saved to: Datasets/dataset_sample.csv

Next steps:
  1. cp Datasets/dataset_sample.csv Datasets/dataset.csv
  2. python train_model.py
```

Sao chép:

```bash
cp Datasets/dataset_sample.csv Datasets/dataset.csv
```

---

### BƯỚC 2B: Nếu CÓ dataset nhưng MODEL chưa train → Train model

```bash
python train_model.py
```

**Chờ 20-30 phút** lần đầu tiên. Output sẽ hiển thị:

```
✓ Best parameters: {...}
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

- F1-score ≥ 0.85? → ✅ Good
- F1-score < 0.80? → ⚠️ Dataset quá nhỏ hoặc features không tốt

---

### BƯỚC 3: Test mô hình cải thiện

```bash
python predictor_improved.py
```

**Output mong đợi:**

```
============================================================
IMPROVED PHISHING DETECTION SYSTEM (Hybrid ML + Rules)
============================================================

============================================================
URL: https://www.youtube.com
============================================================
🎯 Final Prediction: Legitimate
📊 Risk Level: SAFE (Green)
⚡ Risk Score: 15.23%

Scoring Details:
  - ML Model Score: 8.45%
  - Rule-Based Score: 22.1%
  - Scoring Method: Hybrid (ML: 42%, Rules: 58%)
  - Model Confidence: 0.42
  - Phishing probability: 8.45%
  - Legitimate probability: 91.55%

✅ No major red flags detected
```

---

## 📊 Hybrid Scoring Explanation

Mô hình sử dụng **hybrid approach** (kết hợp ML + Rules):

### Khi Model Confident (confidence > 0.7)

```
Final Score = 70% ML + 30% Rules
→ Tin tưởng ML model prediction
```

### Khi Model Not Confident (confidence < 0.3)

```
Final Score = 30% ML + 70% Rules
→ Dùng rule-based (heuristic) để compensate
```

### Ví dụ:

```
URL: youtube.com
  ML Model: Legitimate (93% confidence)
  Rule-Based: Legitimate (whitelist match, HTTPS, etc.)
  → Final: Legitimate ✅

URL: google-secure-login.xyz
  ML Model: Phishing (75% confidence)
  Rule-Based: Phishing (suspicious TLD .xyz, "login" in domain)
  → Final: Phishing ❌
```

---

## 🎯 Khi nào model sẽ chính xác?

| Condition                      | Accuracy          |
| ------------------------------ | ----------------- |
| **Model not trained**          | Very Low (random) |
| **Dataset < 200 samples**      | Low (50-70%)      |
| **Dataset 200-500 samples**    | Medium (70-85%)   |
| **Dataset > 1000 samples**     | High (85-95%)     |
| **Fine-tuned + large dataset** | Very High (>95%)  |

**Hiện tại:** Dùng sample data (400 samples) → dự kiến accuracy ~70-80%

---

## 💡 Để cải thiện hơn

### 1. **Thêm Real Data**

```
Nguồn phishing URLs:
  - Phishtank.com (free database)
  - OpenPhish.com
  - APWG ecrimes corpus
  - Browser security warnings

Nguồn legitimate URLs:
  - Alexa Top 1M sites
  - SimilarWeb
  - Website crawlers
```

### 2. **Cải thiện Features**

Thêm vào `predictor_improved.py`:

```python
# Domain reputation score
# WHOIS age (days)
# DNS records check
# SSL certificate info
# TLS version
# IP geolocation
# Domain registrar reputation
```

### 3. **Dùng Pre-trained Models**

```python
# Nếu muốn accuracy cao ngay lập tức
# Dùng public phishing detection models:
# - urlhaus API
# - VirusTotal API
# - Google SafeBrowsing API
```

---

## 🔧 Troubleshooting

### Q: F1-score vẫn < 0.80 sau khi train?

**A:**

```
1. Dataset quá nhỏ - cần thêm samples
2. Features không tốt - cần improve feature engineering
3. Classes imbalanced - cần balance dataset

Giải pháp:
  - Thêm minimum 1000 samples
  - Cải thiện features (domain age, WHOIS info, etc.)
  - Dùng SMOTE (đã có trong train_model.py)
```

### Q: Model vẫn flag youtube.com là phishing?

**A:**

```
1. Model không confident → dùng rule-based
2. Rule-based nên đánh giá youtube.com là SAFE (whitelist)

Check:
  - python check_model_status.py
  - Kiểm tra model_confidence score
  - Nếu < 0.3 → rule-based sẽ override
```

### Q: Làm sao biết model đã train tốt?

**A:**

```
1. Kiểm tra F1-score ≥ 0.85
2. Kiểm tra ROC-AUC ≥ 0.90
3. Kiểm tra confusion_matrix.png:
   - True Positive rate ≥ 80%
   - False Positive rate ≤ 5%
```

---

## ✅ Checklist

- [ ] Chạy `python check_model_status.py` → check status
- [ ] Nếu không có dataset: `python generate_test_dataset.py`
- [ ] Copy sample dataset: `cp Datasets/dataset_sample.csv Datasets/dataset.csv`
- [ ] Train model: `python train_model.py` (chờ 20-30 phút)
- [ ] Check metrics: F1 ≥ 0.85? ROC-AUC ≥ 0.90?
- [ ] Test: `python predictor_improved.py`
- [ ] Verify: youtube.com → Legitimate? google-secure-login.xyz → Phishing?

---

## 📈 Long-term Improvement

```
Week 1: Setup + Sample Data + Train
  → Accuracy ~70-80%

Week 2: Collect 500+ real phishing URLs
  → Accuracy ~80-85%

Week 3: Improve features (WHOIS, SSL, DNS)
  → Accuracy ~85-90%

Week 4: Collect 2000+ URLs + fine-tune
  → Accuracy >90%

Ongoing: A/B test + collect user feedback
  → Production-grade accuracy >95%
```

---

## 🤝 Cần help?

1. **Model không train:** Check `train_model.py` output cho errors
2. **Dataset issue:** Check `Datasets/dataset.csv` format
3. **Accuracy problem:** Check confusion matrix (confusion_matrix.png)
4. **Features missing:** Read `predictor_improved.py` docstrings

**Chạy test:**

```bash
# Comprehensive test
python check_model_status.py
python generate_test_dataset.py
python train_model.py  # Lâu!
python threshold_optimization.py
python predictor_improved.py
```
