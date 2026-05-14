# Kiến Trúc Dự Án CheckPost

> **CheckPost** — Tiện ích mở rộng trình duyệt phát hiện phishing theo thời gian thực, kết hợp mô hình học máy (ML) và phân tích heuristic.  
> *Khóa luận tốt nghiệp — Phát triển bởi Bùi Thị Huyền Tâm*

---

## 1. Tổng Quan Hệ Thống

CheckPost là hệ thống hai tầng (two-tier) gồm:

| Tầng | Công nghệ | Vai trò |
|------|-----------|---------|
| **Frontend** | Chrome Extension (Manifest V3, JS thuần) | Thu thập URL, hiển thị kết quả cho người dùng |
| **Backend** | Python · FastAPI · Uvicorn | Phân tích URL, chạy mô hình ML, lưu trữ báo cáo |

```
┌──────────────────────────────────────────────────────────────────┐
│                     TRÌNH DUYỆT CHROME                           │
│                                                                  │
│  ┌─────────────────┐    ┌──────────────┐    ┌───────────────┐   │
│  │  contentScript  │◄──►│  background  │◄──►│    popup      │   │
│  │   .js           │    │    .js       │    │   .js/.html   │   │
│  │  (Radar/Scan)   │    │ (Service     │    │  (Bảng kết    │   │
│  │                 │    │  Worker)     │    │   quả)        │   │
│  └────────┬────────┘    └──────┬───────┘    └───────────────┘   │
│           │                   │                                  │
└───────────┼───────────────────┼──────────────────────────────────┘
            │   HTTP REST API   │
            ▼                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                    BACKEND (FastAPI · localhost:8000)             │
│                                                                  │
│   app.py (Router)                                                │
│   ├── /analyze          ── predictor_improved.py                 │
│   ├── /scan-links       ── predictor_improved.py                 │
│   ├── /report           ── models.py + db/db.sqlite3             │
│   └── helpers.py  ·  feature.py                                  │
│                                                                  │
│   MLModels/                                                      │
│   └── phishing_rf_model_tuned.pkl  (Random Forest ~39 MB)        │
│                                                                  │
│   Datasets/                                                      │
│   └── dataset.csv  (~11 K mẫu, 30 features mỗi URL)             │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Frontend — Chrome Extension (Manifest V3)

### 2.1 Cấu Trúc File

```
frontend/
├── manifest.json        # Khai báo quyền & cấu hình extension
├── background.js        # Service Worker — Bộ điều phối trung tâm
├── contentScript.js     # Inject vào mọi trang web — Radar quét link
├── popup.html / .js     # UI bảng điều khiển khi click icon
├── override.html / .js  # Trang cảnh báo khi phát hiện phishing
└── styles.css / overrideStyles.css
```

### 2.2 Luồng Hoạt Động

```
Người dùng duyệt web
        │
        ▼
contentScript.js khởi động (inject vào page)
        │
        ├── MutationObserver theo dõi DOM mới
        │       └── Phát hiện <a href="t.co/..."> trong tweet
        │               └── queueLink(url)  →  pendingUrls.add()
        │
        ├── scheduleBatch()  [debounce 600ms]
        │       └── processBatch()
        │               └── sendMessage { action: "AUTO_SCAN", urls: [...] }
        │                                           │
        ▼                                           ▼
background.js (Service Worker)          background.js nhận message
        │                                           │
        │                               fetch POST /scan-links
        │                                           │
        │                               saveResultsToStorage(tabId, results)
        │                                           │
        │                               sendMessage { action: "UPDATE_POPUP_UI" }
        │
        ▼
contentScript.js nhận kết quả
        └── applyHighlight(el, data)
                ├── Xanh   — SAFE
                ├── Vàng   — WARNING
                └── Đỏ     — DANGEROUS / EXTREMELY DANGEROUS
```

### 2.3 Tính Năng Chính

| Tính năng | Cơ chế |
|-----------|--------|
| **Auto-scan links** | MutationObserver + batch debounce 600ms |
| **Floating check button** | mouseup selection → floating icon → tooltip |
| **Radar indicator** | Fixed button hiển thị số link đang quét |
| **Popup dashboard** | Danh sách kết quả với thông tin country, org, risk score |
| **SPA navigation** | Observer trên `document.head` để phát hiện URL thay đổi |
| **Per-tab storage** | `chrome.storage.local` key: `tab_{tabId}` |
| **Context menu** | Click phải → "URL Check" → gọi `/analyze` |

### 2.4 Quyền Extension

```json
"permissions": ["tabs", "activeTab", "contextMenus", "notifications", "scripting", "storage"]
"host_permissions": ["<all_urls>"]
```

---

## 3. Backend — FastAPI REST API

### 3.1 Cấu Trúc File

```
backend/
├── app.py                    # FastAPI app, router tất cả endpoints
├── predictor_improved.py     # Feature extraction + ML prediction (core)
├── feature.py                # ManualFeatureExtractor (sklearn transformer)
├── helpers.py                # get_domain_name(), check_google_batch()
├── models.py                 # ORM models (Tortoise) + Pydantic schemas
├── train_model.py            # Pipeline huấn luyện mô hình offline
├── MLModels/
│   ├── phishing_rf_model_tuned.pkl         # Model Random Forest (~39 MB)
│   └── phishing_rf_model_tuned_features.pkl # Danh sách tên features
├── Datasets/
│   └── dataset.csv           # Dữ liệu huấn luyện (~11K mẫu)
└── db/
    └── db.sqlite3             # Cơ sở dữ liệu SQLite lưu báo cáo
```

### 3.2 API Endpoints

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/` | Tài liệu API |
| `GET` | `/analyze?url=...` | Phân tích đơn URL (từ context menu / floating tooltip) |
| `POST` | `/scan-links` | Quét hàng loạt URL (từ Auto-Scan trên Twitter) |
| `POST` | `/report` | Người dùng báo cáo phishing |
| `POST` | `/report_mistake` | Báo cáo nhận diện sai (false positive) |
| `GET` | `/reports` | Lấy toàn bộ báo cáo |
| `PUT` | `/report/{id}` | Admin xác nhận/từ chối báo cáo |

### 3.3 Luồng Xử Lý `/scan-links`

```
POST /scan-links  { urls: ["t.co/abc", "t.co/xyz", ...] }
        │
        ├── resolve_batch(urls, max_concurrent=3)
        │       └── get_original_url(short_url)  [per URL]
        │               ├── HTTP GET → follow redirects
        │               ├── Parse meta refresh tag
        │               └── DNS check → HTTP HEAD
        │
        └── asyncio.gather([predict_single_url(r) for r in results])
                └── predict_single_url(url_dict)
                        ├── extract_features_async(final_url)
                        ├── get_risk_report(url, features)
                        └── PhishingReport.filter(url=domain, real=True)
```

### 3.4 Luồng Xử Lý `/analyze`

```
GET /analyze?url=...
        │
        ├── get_domain_name(url)
        ├── extract_features_async(url)
        ├── get_risk_report(url, features)
        └── PhishingReport.filter(url=domain, real=True).exists()
```

---

## 4. Module Phân Tích — `predictor_improved.py`

Đây là **module cốt lõi** của hệ thống, thực hiện ba việc:

### 4.1 Trích Xuất Đặc Trưng (Feature Extraction)

`extract_features_async(url)` trả về dictionary 17+ features:

**Nhóm URL Structure** (không cần network):

| Feature | Mô tả |
|---------|-------|
| `having_IPhaving_IP_Address` | URL chứa địa chỉ IP trực tiếp |
| `URLURL_Length` | Độ dài URL (< 54: safe, 54-88: neutral, >88: suspicious) |
| `Shortining_Service` | URL shortener (bit.ly, t.co, ...) |
| `having_At_Symbol` | Có ký tự `@` trong URL |
| `double_slash_redirecting` | Có `//` sau domain |
| `Prefix_Suffix` | Dấu `-` trong tên miền (typosquatting) |
| `having_Sub_Domain` | Nhiều hơn 2 dấu chấm (many subdomains) |
| `SSLfinal_State` | HTTPS hay không |
| `HTTPS_token` | Token `https` xuất hiện sai chỗ trong URL |
| `port` | Cổng không chuẩn (không phải 80/443) |

**Nhóm Page Content** (cần fetch HTML):

| Feature | Mô tả |
|---------|-------|
| `Favicon` | Favicon từ domain khác |
| `Request_URL` | Tỷ lệ external resources > 50% |
| `URL_of_Anchor` | Tỷ lệ anchor link external |
| `Links_in_tags` | External links trong img/script/link tags |
| `SFH` | Form action trống / mailto: / cross-domain |
| `Submitting_to_email` | Form gửi đến email |
| `Abnormal_URL` | Domain không xuất hiện trong path |
| `Redirect` | Nhiều redirect (> 1 hop) |
| `on_mouseover` | JavaScript onmouseover |
| `RightClick` | Vô hiệu hoá click chuột phải |
| `popUpWidnow` | window.open / alert() |
| `Iframe` | Thẻ `<iframe>` |

**Nhóm WHOIS & DNS**:

| Feature | Mô tả |
|---------|-------|
| `age_of_domain` | Domain > 6 tháng tuổi |
| `Domain_registeration_length` | Còn hạn hơn 365 ngày |
| `DNSRecord` | Có bản ghi DNS |

### 4.2 Scoring Hybrid

```
                    ┌──────────────────────────────┐
                    │      get_risk_report()        │
                    └──────────────────────────────┘
                           │              │
              ┌────────────┘              └────────────┐
              ▼                                        ▼
   ML Model Score (0-100)              Heuristic Score (0-100)
   (Random Forest predict_proba)       (Rule-based, 11 rules)
              │                                        │
              └──────────── Weighted blend ────────────┘
                                   │
                    confidence_weight = min(1.0, model_confidence × 1.5)
                    risk_score = ML × weight + Heuristic × (1 - weight)
                                   │
                    ┌──────────────▼──────────────┐
                    │        Risk Levels           │
                    │  ≥ 80% → EXTREMELY DANGEROUS │
                    │  ≥ 60% → DANGEROUS           │
                    │  ≥ 40% → WARNING             │
                    │  ≥ 20% → CAUTION             │
                    │  < 20% → SAFE                │
                    └──────────────────────────────┘
```

**Whitelist Fast-Track**: Các domain nổi tiếng (google.com, youtube.com, facebook.com, ...) được trả về SAFE ngay lập tức, bỏ qua ML.

### 4.3 Heuristic Rules (11 quy tắc)

| Rule | Điểm cộng |
|------|-----------|
| Suspicious TLD (.tk, .ml, .ga, .cf, .xyz, .gq) | +20 |
| Whitelist domain | -30 |
| Domain mới đăng ký | +15 |
| Không có HTTPS | +20 |
| Địa chỉ IP trong URL | +25 |
| URL shortener | +20 |
| Nhiều redirect | +15 |
| Dấu `-` trong domain | +10 |
| Nhiều subdomain | +10 |
| Form action không hợp lệ | +20 |
| Không có DNS record | +20 |

---

## 5. Mô Hình Machine Learning

### 5.1 Thuật Toán

- **Random Forest Classifier** (scikit-learn)
- File model: `phishing_rf_model_tuned.pkl` (~39 MB, 100-300 cây)
- Output: `predict()` + `predict_proba()` → xác suất phishing

### 5.2 Pipeline Huấn Luyện (`train_model.py`)

```
dataset.csv  (~11K URLs × 30 features)
        │
        ├── STEP 1: load_and_prepare_data()
        │       └── Stratified train/test split (80/20)
        │
        ├── STEP 2: apply_smote()
        │       └── SMOTE cân bằng class imbalance
        │
        ├── STEP 3: hyperparameter_tuning()
        │       └── GridSearchCV (5-fold CV)
        │           └── Params: n_estimators, max_depth,
        │                       min_samples_split, min_samples_leaf,
        │                       max_features, class_weight
        │
        ├── STEP 4: evaluate_model()
        │       ├── Cross-validation metrics (F1, Precision, Recall, ROC-AUC)
        │       ├── confusion_matrix.png
        │       ├── roc_curve.png
        │       └── feature_importance.png
        │
        └── STEP 5: save_trained_model()
                └── phishing_rf_model_tuned.pkl
```

### 5.3 Dataset Features

Dataset UCI phổ biến với 30 đặc trưng binary/ternary (-1, 0, 1) biểu diễn các đặc điểm của URL. Nhãn: `Result` (1 = phishing, -1 = legitimate).

---

## 6. Cơ Sở Dữ Liệu

- **Engine**: SQLite (Tortoise ORM)
- **File**: `backend/db/db.sqlite3`

### Bảng `phishing reports`

| Cột | Kiểu | Mô tả |
|-----|------|-------|
| `id` | INT PK | Auto-increment |
| `url` | VARCHAR(512) | Domain đã báo cáo |
| `reason` | TEXT | Lý do báo cáo |
| `real` | BOOLEAN | Admin xác nhận là thật |
| `created_at` | DATETIME | Thời gian tạo |

### Bảng `Mistake phishing reports`

Tương tự, lưu các trường hợp phát hiện sai (false positive) do người dùng phản hồi.

---

## 7. Giao Tiếp Giữa Các Thành Phần

```
┌─────────────────────────────────────────────────────────┐
│                    GIAO TIẾP NỘI BỘ EXTENSION            │
│                                                         │
│  contentScript ──sendMessage──► background              │
│               ◄─sendResponse──                         │
│                                                         │
│  popup ──────sendMessage──► background                  │
│         ◄───sendResponse──                             │
│                                                         │
│  background ──sendMessage──► contentScript (broadcast)  │
│  background ──sendMessage──► popup (broadcast)          │
│                                                         │
│  Shared State: chrome.storage.local                     │
│    key: "tab_{tabId}"    → scan results per tab         │
│    key: "allowed_{tabId}" → user whitelist              │
│    key: "checkPostState"  → on/off toggle               │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    GIAO TIẾP VỚI BACKEND                 │
│                                                         │
│  background.js ──HTTP POST──► localhost:8000/scan-links  │
│  background.js ──HTTP GET───► localhost:8000/analyze     │
│  popup.js      ──HTTP POST──► localhost:8000/report      │
└─────────────────────────────────────────────────────────┘
```

---

## 8. Luồng Dữ Liệu Toàn Hệ Thống (End-to-End)

```
1. Người dùng mở Twitter/X.com
        │
2. contentScript inject & MutationObserver bắt đầu
        │
3. Phát hiện link t.co/... trong tweet
        │
4. queueLink() → pendingUrls.add() → debounce 600ms
        │
5. processBatch() → sendMessage "AUTO_SCAN"
        │
6. background.js → POST /scan-links [{urls}]
        │
7. Backend: resolve t.co → meta URL → final URL
        │
8. Backend: extract_features_async(final_url)
        │   ├── Phân tích URL structure
        │   ├── Fetch HTML → parse với BeautifulSoup
        │   └── WHOIS query (whoisdomain) + DNS check
        │
9. Backend: get_risk_report()
        │   ├── Random Forest predict_proba()
        │   ├── Heuristic rules score
        │   └── Weighted hybrid score
        │
10. Backend: Check phishing database (SQLite)
        │
11. Backend trả JSON → background.js
        │
12. saveResultsToStorage(tabId, results)
        │
13. sendMessage "UPDATE_POPUP_UI" → popup.js refresh
        │
14. contentScript applyHighlight() → đổi màu link trong trang
        │
15. Người dùng hover/click → xem tooltip chi tiết
```

---

## 9. Stack Công Nghệ

### Backend

| Thư viện | Version | Vai trò |
|----------|---------|---------|
| FastAPI | latest | Web framework async |
| Uvicorn | latest | ASGI server |
| Tortoise ORM | latest | Async ORM cho SQLite |
| httpx | latest | Async HTTP client |
| scikit-learn | latest | Random Forest |
| joblib | latest | Model serialization |
| BeautifulSoup4 | latest | HTML parsing |
| whoisdomain | latest | WHOIS lookup |
| pycountry | latest | Country code lookup |
| pandas | latest | Data manipulation |
| imbalanced-learn | latest | SMOTE oversampling |
| python-Levenshtein | latest | Brand spoofing detection |

### Frontend

| Công nghệ | Vai trò |
|-----------|---------|
| Chrome Extension MV3 | Runtime environment |
| JavaScript (ES2022) | Logic xử lý |
| CSS3 | Styling, animations |
| chrome.storage API | Lưu trữ per-tab |
| chrome.tabs API | Quản lý tab |
| fetch() API | Giao tiếp với backend |
| MutationObserver | DOM change detection |

---

## 10. Giới Hạn Hiện Tại

| Giới hạn | Mô tả |
|----------|-------|
| **URL shortener** | Chỉ hỗ trợ Twitter (t.co), không phải tất cả shortener |
| **Batch size** | Tối đa 10 URL/batch, concurrent 3 |
| **Timeout** | 5 giây mỗi request HTTP |
| **WHOIS blocking** | Chạy đồng bộ qua ThreadPoolExecutor |
| **No caching** | Mỗi URL được phân tích lại từ đầu |
| **Local backend** | Cần chạy server local, không có cloud deployment |
| **Manifest V3** | Service worker bị tắt sau idle, mất state |

---

*Tài liệu này được tạo tự động từ phân tích mã nguồn — CheckPost v1.0*
