## 📖 Giới Thiệu

**CheckPost** là hệ thống phát hiện URL phishing theo thời gian thực được thiết kế đặc biệt cho người dùng mạng xã hội Twitter/X. Hệ thống tự động quét các liên kết xuất hiện trong trang web, phân tích bằng mô hình Machine Learning kết hợp Heuristic, và tô màu cảnh báo trực tiếp trên trình duyệt — tất cả trong vài trăm mili giây.

### ✨ Điểm Nổi Bật

- 🤖 **Mô hình XGBoost Calibrated** — AUC 1.0000, MCC 0.9988 trên tập kiểm tra
- 🔀 **Hybrid Detection** — OR logic giữa ML và 6 Heuristic rules, ưu tiên bảo mật
- ⚡ **Hiệu năng cao** — Warm cache: ~50ms/batch; Cold: ~800ms/batch
- 🔍 **36 Features** — Chuẩn dataset PhiUSIIL 2023 (19 Lexical + 15 Page Content + 2 extra)
- 🗄️ **Dynamic Override** — Database cộng đồng có thể override kết quả ML
- 🎨 **Highlight tức thì** — Tô màu link Xanh/Cam/Đỏ ngay trên trang
## 🚀 Cài Đặt & Chạy

### Yêu Cầu Hệ Thống

- **Python** 3.10 trở lên
- **Google Chrome** (hoặc Chromium)
- **RAM** tối thiểu 512MB (mô hình ML + Whitelist ~1M domains)

### 1. Clone Repository

```bash
git clone https://github.com/Buithihuyentam/CXcheckURLAI.git
cd CXcheckURLAI
```

### 2. Cài Đặt Backend

```bash
# Tạo môi trường ảo (khuyến nghị)
python -m venv myenv
myenv\Scripts\activate        # Windows
# source myenv/bin/activate   # Linux/macOS

# Cài đặt dependencies
pip install -r requirements.txt
```
## 📁 Cấu Trúc Dự Án

```
check-post/
├── frontend/                    # Chrome Extension MV3
│   ├── manifest.json            # Khai báo quyền & cấu hình
│   ├── background.js            # Service Worker — điều phối trung tâm
│   ├── contentScript.js         # Inject vào trang — Radar quét link
│   ├── popup.html / popup.js    # Dashboard UI
│   ├── override.html            # Trang cảnh báo phishing
│   └── styles.css
│
├── backend/                     # FastAPI Python Server
│   ├── app.py                   # Router + URL resolution pipeline
│   ├── predictor_improved.py    # ML Core: features + model + heuristic
│   ├── helpers.py               # Utility functions
│   ├── models.py                # Tortoise ORM models + Pydantic schemas
│   ├── train_model_final.py     # Pipeline huấn luyện offline
│   ├── MLModels/
│   │   ├── phishing_xgb_calibrated.pkl   # Model đã huấn luyện
│   │   ├── phishing_xgb_features.pkl     # 36 feature names
│   │   └── optimal_threshold.json        # threshold = 0.7433
│   ├── Datasets/
│   │   ├── top-1m.csv                    # Tranco Top-1M whitelist
│   │   └── PhiUSIIL_Phishing_URL_Dataset.csv
│   └── db/
│       └── db.sqlite3                    # SQLite database
│
├── docs/
│   └── ARCHITECTURE.md          # Tài liệu kiến trúc chi tiết
├── requirements.txt
└── README.md
