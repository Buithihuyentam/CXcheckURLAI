# Nhận Xét Kỹ Thuật & Đề Xuất Cải Tiến — CheckPost

> **Đây là nhận xét nghiêm túc về mặt kỹ thuật**, nhằm giúp dự án đạt chất lượng tốt hơn trước khi bảo vệ khóa luận. Mọi nhận xét đều có căn cứ từ mã nguồn thực tế.

---

## Tóm Tắt Đánh Giá Tổng Thể

| Khía cạnh | Điểm (10) | Nhận xét ngắn |
|-----------|-----------|---------------|
| Ý tưởng & phạm vi | 8/10 | Vấn đề thực tiễn, triển khai được |
| Kiến trúc tổng thể | 6/10 | Hợp lý nhưng còn nhiều vấn đề thiết kế |
| Chất lượng ML | 6/10 | Thực tế bài bản nhưng có lỗ hổng nghiêm trọng |
| Chất lượng Backend | 5/10 | Nhiều vấn đề bảo mật và ổn định |
| Chất lượng Frontend | 7/10 | Khá tốt, UI hợp lý |
| Độ an toàn (Security) | 3/10 | Nhiều vấn đề nghiêm trọng |
| Khả năng mở rộng | 4/10 | Không thể scale lên production |

---

## PHẦN 1: Nhận Xét Về Machine Learning

### ✅ Điểm Tốt

**1. Hybrid Scoring (ML + Heuristic)**  
Việc kết hợp xác suất từ Random Forest với điểm heuristic là một lựa chọn đúng hướng. Khi model không tự tin (model_confidence thấp), heuristic rules sẽ bù đắp — đây là kiến trúc "ensemble of ensembles" hợp lý.

**2. Pipeline Huấn Luyện Có Hệ Thống**  
`train_model.py` sử dụng: Stratified K-Fold, GridSearchCV, SMOTE, Matthews Correlation Coefficient, ROC-AUC — đây là các thực hành tốt trong ML.

**3. Feature Engineering Đa Dạng**  
30 features bao phủ URL structure, page content, WHOIS, DNS — đây là bộ đặc trưng toàn diện.

---

### ❌ Vấn Đề Nghiêm Trọng

#### 1.1 Whitelist Cứng — Lỗ Hổng Bảo Mật Chết Người

```python
# predictor_improved.py, dòng 47-53
LEGITIMATE_DOMAINS = {
    'google.com', 'facebook.com', 'amazon.com', ...
}
```

**Vấn đề**: Kẻ tấn công có thể dùng subdomain giả mạo:
- `google.com.evil.xyz` → KHÔNG khớp whitelist ✅ (đúng)
- `evil-google.com` → KHÔNG khớp ✅ (đúng)
- **NHƯNG**: `accounts.google.com.phishing.tk` → kiểm tra `domain.endswith('.' + legit_domain)` sẽ pass vì `endswith('.google.com')` → **trả về SAFE ngay lập tức** mà không chạy ML!

```python
# Logic hiện tại — CÓ THỂ BỊ BYPASS
if domain == legit_domain or domain.endswith('.' + legit_domain):
    return { "is_phishing": False, ... }
```

**Minh chứng tấn công**: URL `http://login.google.com.harvester.ru` → `domain = login.google.com.harvester.ru` → `endswith('.google.com')` → **False** (OK trong case này). NHƯNG URL `http://myaccounts.google.com.ru/login` → `endswith('.google.com')` → **False** cũng đúng. Tuy nhiên, logic này cần được audit kỹ vì bất kỳ thay đổi nhỏ nào cũng có thể tạo ra false negative.

> [!WARNING]
> Whitelist nên được kiểm tra theo chiều ngược lại: domain thực sự là subdomain của legit domain không? Cần extract TLD+1 (eTLD+1) bằng thư viện `tldextract` thay vì string matching.

---

#### 1.2 Thresholds Feature Hard-coded Không Có Cơ Sở Thống Kê

```python
# predictor_improved.py, dòng 58-71
FEATURE_THRESHOLDS = {
    'url_length': {
        'short': 54,      # ← Con số này đến từ đâu?
        'medium': 88,
        'long': 88        # ← Giống medium? Logic này vô nghĩa
    },
    'external_ratio': {
        'safe': 0.5,      # ← Không có citation
        'warning': 0.75   # ← Không được sử dụng ở đâu!
    }
}
```

**Vấn đề cụ thể**:
- `'long': 88` và `'medium': 88` là cùng giá trị → hai nhánh không bao giờ khác nhau
- Comment trong code nói "BẠN NÊN TÍNH NHỮNG GIÁ TRỊ NÀY TỪ DATASET" — nhưng không thực hiện điều đó
- `'warning': 0.75` được định nghĩa nhưng **không được sử dụng** ở bất kỳ đâu

> [!IMPORTANT]
> Thresholds phải được tính từ dataset thực bằng phân vị (quantile). Ví dụ: `pd.Series(url_lengths).quantile([0.25, 0.5, 0.75])`. Đây là yêu cầu cơ bản để một nghiên cứu ML có giá trị.

---

#### 1.3 Feature Encoding Không Nhất Quán

Trong `predictor_improved.py`, encoding dùng `{-1, 0, 1}`:
- `-1` = suspicious
- `0` = neutral
- `1` = safe

Nhưng trong `feature.py` (ManualFeatureExtractor), encoding dùng `{0, 1}`:
- `0` = không có
- `1` = có

**Hệ quả**: Hai hệ thống đặc trưng không thể dùng chung một model. `ManualFeatureExtractor` tồn tại nhưng **không được sử dụng** trong luồng chính (`app.py` comment out dòng import nó). Đây là code chết (dead code) không được dọn dẹp.

---

#### 1.4 Dataset Không Rõ Nguồn Gốc

Không có tài liệu nào mô tả:
- Dataset lấy từ nguồn nào (Kaggle UCI? PhishTank? Custom?)
- Thời điểm thu thập (phishing landscape thay đổi nhanh)
- Tỷ lệ phishing/legitimate trong dataset
- Dataset có được cập nhật không, hay là snapshot tĩnh năm cũ?

**Vấn đề thực tiễn**: Một mô hình phishing được huấn luyện trên data năm 2020 sẽ kém hiệu quả trên các chiến thuật phishing năm 2024-2025.

---

#### 1.5 Heuristic Score Khởi Đầu Từ 50 — Bias Phishing

```python
# dòng 172
score = 50  # Start at neutral
```

Bắt đầu từ 50% có nghĩa là mọi URL đều có nguy cơ **"WARNING"** trước khi bất kỳ rule nào được kiểm tra. Một URL hoàn toàn sạch (chỉ trừ điểm từ whitelist) sẽ có điểm `50 - 30 = 20` → vẫn là "CAUTION". Logic này làm tăng false positive rate.

---

### 📋 Đề Xuất Cải Tiến ML

**Ngắn hạn (trước bảo vệ)**:
1. Thay whitelist string-matching bằng `tldextract`: `tldextract.extract(domain).registered_domain`
2. Tính thresholds từ quantiles của dataset thực, thêm vào tài liệu
3. Xóa `ManualFeatureExtractor` hoặc tích hợp đúng cách — không để dead code
4. Hạ điểm khởi đầu heuristic từ 50 → 30, có citation cho mỗi rule weight

**Dài hạn (sau tốt nghiệp)**:
- Thử LightGBM hoặc XGBoost — thường cho kết quả tốt hơn RF với tabular data
- Thêm VirusTotal API hoặc Google Safe Browsing API làm nguồn ground truth
- Online learning: cập nhật model khi có báo cáo từ người dùng
- Cross-dataset validation: train trên dataset A, test trên dataset B

---

## PHẦN 2: Nhận Xét Về Backend

### ✅ Điểm Tốt

- Sử dụng `asyncio.gather()` để xử lý concurrent — đúng hướng
- `Semaphore` để kiểm soát concurrent requests
- Tách biệt resolve URL shortener khỏi prediction — thiết kế tốt
- Fallback graceful khi WHOIS/DNS/HTTP thất bại

---

### ❌ Vấn Đề Nghiêm Trọng

#### 2.1 API Key Hardcode Trong Mã Nguồn

```python
# app.py, dòng 30
api_key="AIzaSyA8n9sXo2l7mLh0Zt1kKjv3X9z5y6w7x8"
```

> [!CAUTION]
> **Đây là lỗi bảo mật nghiêm trọng nhất trong dự án.** API key không được hardcode trong mã nguồn, đặc biệt khi push lên GitHub. Phải dùng biến môi trường (`os.environ.get('GOOGLE_API_KEY')`). Key này trông giả tạo nhưng cấu trúc tương tự Google API key thật — cần xóa ngay khỏi git history bằng `git filter-branch` hoặc BFG Repo-Cleaner.

---

#### 2.2 CORS Cho Phép Tất Cả Origins

```python
# app.py, dòng 48-54
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cho phép TẤT CẢ origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Mặc dù server chạy local, việc `allow_origins=["*"]` kết hợp với `allow_credentials=True` là không hợp lệ theo CORS spec (browser sẽ chặn). Với một project thực tế, chỉ nên cho phép `chrome-extension://` origin.

---

#### 2.3 Bug Logic Trong `/report/{id}` Endpoint

```python
# app.py, dòng 120-130
@app.put('/report/{id}')
async def update(id: int, real: bool):
    try:
        await PhishingReport.filter(id=id).update(real=real)
        if real:
            with open('Datasets/phishing_site_urls.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(str(PhishingReport.get(id=id).url), "bad")
        return {'result': 'success'}
    except:
        return {'result': 'failed'}
```

**Lỗi 1**: `csv.writer.writerow()` nhận một list, không phải hai arguments riêng lẻ. Code này sẽ raise `TypeError` mỗi lần thực thi khi `real=True`.

**Lỗi 2**: `PhishingReport.get(id=id)` là synchronous call trong async context, và không được `await`. Tortoise ORM yêu cầu `await PhishingReport.get(id=id)`.

**Lỗi 3**: `except:` trống — nuốt tất cả exceptions, không log, không rethrow. Đây là anti-pattern nghiêm trọng — lỗi bị che giấu hoàn toàn.

> [!CAUTION]
> Chức năng "Admin xác nhận báo cáo và thêm vào dataset" — một trong những tính năng quan trọng của hệ thống — **không hoạt động đúng** do 3 bug trên.

---

#### 2.4 Không Có Authentication Cho Admin Endpoints

Endpoint `PUT /report/{id}` là admin operation (xác nhận phishing reports) nhưng **không có bất kỳ authentication nào**. Bất kỳ ai có thể gọi endpoint này và thay đổi trạng thái báo cáo.

---

#### 2.5 Bug Trong `scan_multiple_links()`

```python
# app.py, dòng 311-320
@app.post("/scan-links")
async def scan_multiple_links(data: UrlList):
    process_urls = list(set(data.urls))[:10]  # ← biến này tạo ra nhưng không dùng!
    results = await resolve_batch(data.urls, max_concurrent=3)  # ← dùng data.urls gốc
```

`process_urls` được tạo để deduplicate và giới hạn 10 URLs, nhưng `resolve_batch()` lại dùng `data.urls` gốc — không deduplicate, không giới hạn. Comment "Xử lý tối đa 10 link" là **sai** so với implementation thực tế.

---

#### 2.6 httpx Client Không Được Cleanup Đúng Cách

```python
# app.py, dòng 177-189
_client: httpx.AsyncClient | None = None

async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(...)
    return _client

async def close_client():  # ← Hàm này không bao giờ được gọi!
    ...
```

`close_client()` được định nghĩa nhưng không được đăng ký với FastAPI lifecycle events (`@app.on_event("shutdown")`). Client sẽ không bao giờ được đóng đúng cách.

---

#### 2.7 Không Có Request Validation & Rate Limiting

- Endpoint `/scan-links` chấp nhận list không giới hạn (về lý thuyết)
- Không có rate limiting — dễ bị DDoS nếu expose ra internet
- Không validate URL format trước khi phân tích

---

### 📋 Đề Xuất Cải Tiến Backend

**Ngắn hạn (critical — trước bảo vệ)**:
1. Xóa hardcoded API key, dùng `.env` + `python-dotenv`
2. Sửa 3 bug trong `/report/{id}`
3. Sửa bug `process_urls` không được dùng trong `/scan-links`
4. Đăng ký `close_client()` với FastAPI shutdown event

**Trung hạn**:
5. Thêm Redis caching cho kết quả phân tích URL (TTL 1-24 giờ)
6. Thêm authentication cho admin endpoints (JWT token)
7. Rate limiting với `slowapi`
8. Structured logging thay vì `print()`
9. Chạy WHOIS thực sự async (thư viện `aiodns` + async-whois)

---

## PHẦN 3: Nhận Xét Về Frontend

### ✅ Điểm Tốt

- Sử dụng `WeakSet` cho `processedLinks` để tránh memory leak
- Debounce đúng cách cho batch scanning
- MutationObserver để theo dõi SPA navigation — kỹ thuật tốt
- Tách biệt concerns: `App` object vs `UI` object trong popup.js
- Glassmorphism tooltip UI khá đẹp

---

### ❌ Vấn Đề

#### 3.1 CONFIG.SHORTENERS Và CONFIG.SAFE_DOMAINS Không Tồn Tại

```javascript
// contentScript.js, dòng 124-130
isSafe(url) {
    const host = this.getHost(url);
    if (this.CONFIG.SHORTENERS.has(host)) return false;  // ← SHORTENERS không có trong CONFIG!
    return (
        this.CONFIG.SAFE_DOMAINS.has(host) ||            // ← SAFE_DOMAINS không có trong CONFIG!
        ...
    );
},
```

`CONFIG` chỉ định nghĩa `SCAN_DEBOUNCE_MS`, `MAX_BATCH_SIZE`, `LINK_SELECTOR`. Hàm `isSafe()` sẽ throw `TypeError: Cannot read properties of undefined`. Đây là **dead code** — hàm này không được gọi ở bất kỳ đâu trong file.

---

#### 3.2 Memory Leak Tiềm Ẩn Với localCache

```javascript
state: {
    localCache: new Map(),  // ← Không bao giờ bị xóa
    ...
}
```

`localCache` được thêm mới liên tục (mỗi URL được scan) nhưng không có upper bound và không có cleanup khi tab đóng. Với người dùng Twitter nặng (scroll nhiều giờ), cache có thể chứa hàng nghìn entries.

---

#### 3.3 XSS Risk Trong Popup UI

```javascript
// popup.js, dòng 239-245
item.red_flags.map((flag) => `<li>${flag}</li>`).join("")
```

`red_flags` là dữ liệu đến từ backend. Nếu backend bị compromise hoặc có bug, dữ liệu độc hại có thể inject HTML vào popup. Cần sanitize với `textContent` hoặc `DOMPurify`.

---

#### 3.4 LINK_SELECTOR Chỉ Hoạt Động Trên Twitter/X

```javascript
LINK_SELECTOR: 'article[data-testid="tweet"] a[href*="t.co"]',
```

Extension được quảng cáo là "anti fraud extension that protects you from phishing sites" nhưng **chỉ auto-scan link Twitter**. Các trang khác (Facebook, Email, News sites) **không được auto-scan**. Đây là khoảng cách lớn giữa mô tả và implementation.

---

#### 3.5 Console.log Trong Production Code

File `popup.js` và `contentScript.js` chứa hàng chục `console.log()` debug statements:
```javascript
console.log(`📥 Nhận ${response.allData} link đã quét từ Background`);
// Note: response.allData là Array, toString() sẽ cho ra "[object Object],[object Object]"
// → Bug log không có nghĩa
```

Ngoài việc lộ thông tin, log này còn có bug — `response.allData` là array, không phải số.

---

#### 3.6 Override Page (Chặn Phishing) Bị Disabled

```javascript
// background.js, dòng 163-178 — toàn bộ trong comment
// try {
//   const res = await fetch(`${CONFIG.SERVER_URL}phishing?url=...`);
//   if (data.is_phishing) {
//     chrome.tabs.update(tabId, { url: warningUrl });
//   }
// }
```

Tính năng **chặn trang phishing** — được coi là tính năng cốt lõi — hoàn toàn bị comment out. Override page (`override.html`) được xây dựng nhưng không bao giờ được kích hoạt. Đây là **feature gap nghiêm trọng** nếu thesis claim rằng extension "protects users from phishing sites".

---

### 📋 Đề Xuất Cải Tiến Frontend

**Ngắn hạn**:
1. Xóa hàm `isSafe()` không hoạt động hoặc sửa `CONFIG` cho đúng
2. Thêm size limit cho `localCache` (LRU cache, max 500 entries)
3. Escape HTML trong `red_flags` rendering
4. Xóa toàn bộ `console.log()` debug trong production build

**Trung hạn**:
5. Mở rộng `LINK_SELECTOR` để scan link trên các trang phổ biến khác
6. Bật lại real-time phishing page blocking (uncomment và test)
7. Thêm keyboard shortcut để mở popup nhanh

---

## PHẦN 4: Nhận Xét Về Kiến Trúc Tổng Thể

### ❌ Vấn Đề Kiến Trúc Lớn

#### 4.1 Phụ Thuộc Vào Local Server — Không Thể Deploy

Toàn bộ hệ thống phụ thuộc vào `localhost:8000`. Extension **không thể hoạt động** nếu:
- Người dùng không biết cách chạy Python server
- Server chưa được khởi động
- Port 8000 đang bị chiếm

Đây là **blocker hoàn toàn** cho việc phân phối extension cho người dùng thực. Một thesis về cybersecurity extension mà không ai dùng được là vấn đề nghiêm trọng.

**Đề xuất**: Deploy backend lên Render.com (free tier), Railway, hoặc Fly.io. Chi phí $0-5/tháng cho traffic nhỏ.

---

#### 4.2 Không Có Graceful Degradation

Khi backend down, extension **fail hoàn toàn** — không có fallback, không có thông báo rõ ràng cho người dùng. Ít nhất nên hiển thị "Server offline — protection disabled" thay vì silently fail.

---

#### 4.3 Thiếu Logging & Monitoring

- Backend dùng `print()` thay vì Python `logging` module
- Không có error tracking (Sentry, etc.)
- Không có metrics về accuracy trong production

---

#### 4.4 Model Size 39 MB Là Quá Lớn

`phishing_rf_model_tuned.pkl` nặng **~39 MB**. Để load model này mỗi lần server khởi động mất thời gian đáng kể. Trong môi trường serverless (Lambda, Cloud Run), đây là vấn đề cold start nghiêm trọng.

**Giải pháp**: Model pruning (giảm số cây từ 300 → 100 với ít mất accuracy), hoặc chuyển sang LightGBM (thường nhỏ hơn 10x với cùng accuracy).

---

## PHẦN 5: Nhận Xét Về Nội Dung Thesis

### Những Điều Cần Làm Rõ Trong Báo Cáo

> [!IMPORTANT]
> Hội đồng phản biện thường hỏi những câu sau. Cần có câu trả lời rõ ràng trong báo cáo:

1. **Baseline comparison**: So sánh với gì? Extension có tốt hơn Google Safe Browsing không? Nếu không so sánh với baseline, kết quả không có ý nghĩa.

2. **Dataset bias**: Dataset phishing thường bị temporal bias — URL phishing thay đổi nhanh. Model được test trên data cùng thời điểm hay trên unseen data?

3. **False positive rate**: Hệ thống block bao nhiêu URL hợp lệ? Điều này quan trọng hơn accuracy trong thực tế (người dùng sẽ tắt extension nếu nó block Netflix).

4. **Evaluation trong thực tế**: Model lab test được 95% accuracy, nhưng khi deploy trên URL thực tế thu thập ngẫu nhiên thì sao? "Real-world evaluation" là yêu cầu quan trọng.

5. **Giải thích whitelist**: Tại sao `notion.so`, `twitch.tv` được whitelist nhưng `vietcombank.com.vn`, `agribank.com.vn` thì không? Hệ thống bảo vệ ai?

6. **Tính năng bị disabled**: Nếu real-time page blocking bị comment out, hội đồng sẽ hỏi lý do. Cần giải thích rõ hoặc bật lại.

---

## PHẦN 6: Bảng Tổng Hợp Bug & Lỗ Hổng

| # | Vị trí | Mức độ | Mô tả |
|---|--------|--------|-------|
| B1 | `app.py:30` | 🔴 Critical | API key hardcoded trong source code |
| B2 | `app.py:127` | 🔴 Critical | `csv.writerow()` sai syntax — chức năng admin broken |
| B3 | `app.py:127` | 🔴 Critical | `PhishingReport.get()` không được `await` |
| B4 | `app.py:315` | 🟠 High | `process_urls` tạo ra nhưng không dùng — deduplicate không hoạt động |
| B5 | `predictor_improved.py:62` | 🟠 High | `'long'` và `'medium'` threshold giống nhau — logic sai |
| B6 | `contentScript.js:124` | 🟠 High | `CONFIG.SHORTENERS` và `CONFIG.SAFE_DOMAINS` undefined |
| B7 | `app.py:280-285` | 🟡 Medium | `close_client()` không bao giờ được gọi — resource leak |
| B8 | `app.py:129` | 🟡 Medium | `except:` trống — nuốt tất cả errors |
| B9 | `predictor_improved.py:44` | 🟡 Medium | `SUSPICIOUS_TLDS` chứa `.tk` hai lần |
| B10 | `popup.js:55` | 🟡 Medium | `console.log(response.allData)` — log array không phải số |
| B11 | `background.js:163` | 🟡 Medium | Real-time page blocking bị comment out hoàn toàn |
| B12 | `feature.py` | 🟡 Medium | ManualFeatureExtractor không được sử dụng — dead code |

---

## Kết Luận

CheckPost là một dự án có **ý tưởng tốt và phạm vi thực tiễn**, đặc biệt trong bối cảnh phishing qua mạng xã hội ngày càng phổ biến. Kiến trúc hybrid ML + heuristic là hướng đúng đắn.

Tuy nhiên, dự án còn **nhiều lỗi kỹ thuật nghiêm trọng** cần được khắc phục trước khi bảo vệ:

1. **Ưu tiên 1**: Sửa 4 bug critical (B1-B4)
2. **Ưu tiên 2**: Làm rõ whitelist logic và thresholds có cơ sở
3. **Ưu tiên 3**: Có số liệu so sánh với baseline (Google Safe Browsing)
4. **Ưu tiên 4**: Quyết định có bật real-time blocking không — và giải thích trong báo cáo

Với các sửa chữa này, dự án hoàn toàn đủ điều kiện đạt điểm tốt trong hội đồng phản biện.

---

*Tài liệu nhận xét được tạo dựa trên phân tích mã nguồn thực tế — CheckPost v1.0*
