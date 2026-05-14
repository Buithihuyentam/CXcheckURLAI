"""
compute_thresholds.py
=====================
Tính toán các ngưỡng (thresholds) và trọng số heuristic có căn cứ
từ dataset thực tế (Datasets/dataset.csv).

Nguồn tham chiếu:
  Mohammad, R.M., Thabtah, F. & McCluskey, T.L. (2015).
  "Phishing Websites Features". UCI ML Repository.
  DOI: 10.24432/C51W2X
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
import json

DATASET_PATH = os.path.join(os.path.dirname(__file__), "Datasets", "dataset.csv")
MODEL_PATH   = os.path.join(os.path.dirname(__file__), "MLModels", "phishing_rf_model_tuned.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "MLModels", "phishing_rf_model_tuned_features.pkl")
OUTPUT_PATH  = os.path.join(os.path.dirname(__file__), "MLModels", "thresholds_calibrated.json")

# ===========================================================================
# 1. Load dataset
# ===========================================================================

df = pd.read_csv(DATASET_PATH)
phish = df[df["Result"] == 1]
legit  = df[df["Result"] == -1]

N_total = len(df)
N_phish = len(phish)
N_legit = len(legit)
base_rate = N_phish / N_total  # Prior probability của phishing

print("=" * 70)
print("DATASET STATISTICS")
print("=" * 70)
print(f"Total samples  : {N_total:,}")
print(f"Phishing (1)   : {N_phish:,} ({base_rate*100:.1f}%)")
print(f"Legitimate (-1): {N_legit:,} ({(1-base_rate)*100:.1f}%)")
print()

# ===========================================================================
# 2. URL Length Thresholds — tra lại paper gốc
# ===========================================================================
# Paper: Mohammad et al. 2015, Table 1, Feature "Length of URL"
# - Safe     (1) : length < 54
# - Suspicious(0): 54 <= length <= 75
# - Phishing (-1): length > 75
#
# Dataset encode feature này là {-1, 0, 1} theo paper.
# Phân phối trong dataset:
url_len_dist = df["URLURL_Length"].value_counts().sort_index()

print("=" * 70)
print("URL LENGTH ENCODING (theo Mohammad et al. 2015)")
print("=" * 70)
print("Theo paper gốc UCI (Table 1):")
print("  value =  1 (Safe)      : URL length < 54 ký tự")
print("  value =  0 (Suspicious): 54 <= URL length <= 75 ký tự")
print("  value = -1 (Phishing)  : URL length > 75 ký tự")
print()
print("Phân bố trong dataset:")
for v, cnt in url_len_dist.items():
    label = {1: "Safe (< 54)",  0: "Suspicious (54-75)", -1: "Phishing (> 75)"}
    p_phish = (df[df["URLURL_Length"] == v]["Result"] == 1).sum() / cnt * 100
    print(f"  {v:+2d} [{label.get(v, v):<22}]: {cnt:5d} samples  — {p_phish:.1f}% phishing")

print()
print(">>> FIX: Thay FEATURE_THRESHOLDS['url_length'] thành:")
print("         'short': 54   (same — đúng rồi)")
print("         'medium': 75  (sai trong code: 88 → phải là 75 theo paper)")
print("         'long': 75    (sai trong code: 88 → phải là 75 theo paper)")

# ===========================================================================
# 3. Heuristic Rule Weights — tính từ Log-Likelihood Ratio
# ===========================================================================
# Phương pháp: Naive Bayes log-likelihood ratio (log-odds)
#
# W(feature) = log [ P(feature=-1 | phishing) / P(feature=-1 | legit) ]
#
# Điểm dương = feature này liên quan đến phishing
# Điểm càng cao → rule càng mạnh
#
# Sau đó scale về thang 0-100 bằng MinMax normalization.

print()
print("=" * 70)
print("HEURISTIC RULE WEIGHTS — LOG-LIKELIHOOD RATIO FROM DATASET")
print("=" * 70)
print("Công thức: LLR = log [ P(feature=-1 | class=phishing)")
print("                     / P(feature=-1 | class=legit) ]")
print()

# Các features được dùng trong heuristic score hiện tại
HEURISTIC_FEATURES = [
    "having_IPhaving_IP_Address",  # IP in URL
    "SSLfinal_State",              # No HTTPS
    "Shortining_Service",          # URL shortener
    "Redirect",                    # Multiple redirects
    "Prefix_Suffix",               # Hyphen in domain
    "having_Sub_Domain",           # Multiple subdomains
    "SFH",                         # Form submission target
    "DNSRecord",                   # No DNS record
    "age_of_domain",               # Domain age
    "URLURL_Length",               # URL length
]

eps = 1e-6  # smoothing để tránh log(0)

llr_dict = {}

print(f"{'Feature':<35} {'P(-1|phish)':>12} {'P(-1|legit)':>12} {'LLR':>8} {'Old pts':>8} {'New pts':>8}")
print("-" * 85)

# Old points theo code hiện tại
old_points = {
    "having_IPhaving_IP_Address": 25,
    "SSLfinal_State": 20,
    "Shortining_Service": 20,
    "Redirect": 15,
    "Prefix_Suffix": 10,
    "having_Sub_Domain": 10,
    "SFH": 20,
    "DNSRecord": 20,
    "age_of_domain": 15,
    "URLURL_Length": 0,   # không có trong old heuristic
}

for feat in HEURISTIC_FEATURES:
    if feat not in df.columns:
        continue

    # P(feature = -1 | class = phishing)
    p_neg_given_phish = (phish[feat] == -1).sum() / N_phish

    # P(feature = -1 | class = legit)
    p_neg_given_legit = (legit[feat] == -1).sum() / N_legit

    # Log-likelihood ratio
    llr = np.log((p_neg_given_phish + eps) / (p_neg_given_legit + eps))
    llr_dict[feat] = llr

    old = old_points.get(feat, 0)
    print(f"{feat:<35} {p_neg_given_phish:>12.4f} {p_neg_given_legit:>12.4f} {llr:>8.3f} {old:>8} {'→ TBD':>8}")

# Scale LLR về [0, 25] (điểm tối đa 25 cho feature mạnh nhất)
max_llr = max(v for v in llr_dict.values() if v > 0)
MIN_PTS = 0
MAX_PTS = 25

print()
print("=" * 70)
print("SCALED WEIGHTS (0-25 scale, proportional to LLR)")
print("=" * 70)
print()

scaled = {}
for feat, llr in llr_dict.items():
    if llr <= 0:
        # Feature này KHÔNG discriminate phishing khi = -1
        pts = 0
        direction = "KHÔNG có ý nghĩa phishing"
    else:
        pts = round(llr / max_llr * MAX_PTS)
        direction = ""
    scaled[feat] = pts

    old = old_points.get(feat, 0)
    change = f"{'↑' if pts > old else '↓' if pts < old else '='}"
    print(f"  {feat:<35} LLR={llr_dict[feat]:+.3f}  → {pts:2d} pts  (was {old}) {change}  {direction}")

# ===========================================================================
# 4. Base score và heuristic calibration
# ===========================================================================
print()
print("=" * 70)
print("BASE SCORE CALIBRATION")
print("=" * 70)
print()
print(f"Prior P(phishing) trong dataset = {base_rate*100:.1f}%")
print()
print("Hiện tại: base_score = 50 (quá cao — bias về phishing)")
print()
print("Đề xuất 1 — Prior-based:")
print(f"  base_score = {base_rate*100:.0f}  (bằng tỷ lệ phishing trong dataset)")
print()
print("Đề xuất 2 — Neutral / Conservative:")
print("  base_score = 0  (bắt đầu từ 0, chỉ tăng khi phát hiện dấu hiệu)")
print("  → Cách này rõ ràng nhất về mặt logic")
print()
print("  KHUYẾN NGHỊ: Dùng base_score = 0")
print("  Lý do: Mỗi rule là evidence CHỐNG LẠI URL này.")
print("         Không có evidence → không có điểm phishing.")
print()

# ===========================================================================
# 5. Confidence Score Formula
# ===========================================================================
print("=" * 70)
print("CONFIDENCE SCORE — CĂN CỨ TOÁN HỌC")
print("=" * 70)
print()
print("Công thức hiện tại:")
print("  confidence_weight = min(1.0, model_confidence * 1.5)")
print("  risk_score = ml_score * weight + heuristic * (1 - weight)")
print()
print("Vấn đề: Hệ số 1.5 không có cơ sở.")
print()
print("Phương án A — Sigmoid-based mixing:")
print("  σ(x) = 1 / (1 + e^(-k*(x - 0.5)))")
print("  weight = σ(model_confidence)  → smooth transition, có toán học")
print("  k = 10 (steepness, tuneable)")
print()
print("Phương án B — Isotonic calibration (Platt scaling):")
print("  Calibrate predict_proba() của RF bằng CalibratedClassifierCV")
print("  Sau đó dùng calibrated probability trực tiếp làm risk_score")
print("  → Đây là chuẩn mực trong ML production")
print()
print("Phương án C — Linear mixing với học thuật citation:")
print("  weight = model_confidence  (không nhân 1.5)")
print("  → Đơn giản, trung thực, có thể giải thích")
print("  Nguồn: Lỗi 1.5 là arbitrary — xóa đi để đơn giản hóa")
print()

# ===========================================================================
# 6. External ratio thresholds
# ===========================================================================
print("=" * 70)
print("EXTERNAL RATIO THRESHOLDS — CĂN CỨ TỪ DATASET")
print("=" * 70)
print()

# Request_URL trong dataset: -1 khi external ratio > threshold_safe
# Tìm xác suất phishing theo Request_URL
for feat in ["Request_URL", "URL_of_Anchor", "Links_in_tags"]:
    if feat in df.columns:
        dist = df[feat].value_counts().sort_index()
        print(f"{feat}:")
        for v, cnt in dist.items():
            p = (df[df[feat] == v]["Result"] == 1).sum() / cnt * 100
            label = {1: "safe (internal)", 0: "neutral", -1: "suspicious (external)"}
            print(f"  {v:+2d} [{label.get(v, '?'):<25}]: {cnt:5d} samples — {p:.1f}% phishing")
        print()

print("Kết luận external ratio:")
print("  - Request_URL=-1 (>50% external): P(phishing) = 40.5%")
print("  - Threshold 50% (0.5) là giá trị hợp lý từ paper gốc")
print("  - Có thể tính chính xác hơn bằng ROC threshold optimization")
print()

# ===========================================================================
# 7. Anchor ratio thresholds
# ===========================================================================
print("=" * 70)
print("ANCHOR RATIO THRESHOLDS — TỪ PAPER GỐC UCI")
print("=" * 70)
print()
print("Theo Mohammad et al. 2015, Table 1, Feature 'Anchor URL':")
print("  value =  1 (Safe)      : % của links trỏ về same domain < 31%")
print("  value =  0 (Suspicious): 31% <= % <= 67%")
print("  value = -1 (Phishing)  : % > 67%")
print()
print("Note: Đây là % external links (không phải % internal)")
print("  safe anchor_ratio: < 0.31 external  → code hiện tại ĐÚNG")
print("  medium: < 0.67 external              → code hiện tại ĐÚNG")
print()

# ===========================================================================
# 8. Xuất kết quả
# ===========================================================================
output = {
    "_source": "Mohammad, R.M., Thabtah, F. & McCluskey, T.L. (2015). Phishing Websites Features. UCI ML Repository. DOI: 10.24432/C51W2X",
    "_computed_from": "Datasets/dataset.csv",
    "_dataset_stats": {
        "total": int(N_total),
        "phishing": int(N_phish),
        "legitimate": int(N_legit),
        "base_phishing_rate": round(base_rate, 4),
    },
    "url_length_thresholds": {
        "_note": "Theo paper gốc Mohammad et al. 2015. Value=1: safe, 0: suspicious, -1: phishing",
        "short_upper": 54,
        "medium_upper": 75,
    },
    "external_ratio_thresholds": {
        "_note": "Theo paper gốc, 50% external resources là threshold cho Request_URL",
        "safe": 0.31,
        "suspicious": 0.50,
    },
    "anchor_ratio_thresholds": {
        "_note": "Theo paper gốc, 31% và 67% là threshold cho URL_of_Anchor",
        "safe": 0.31,
        "medium": 0.67,
    },
    "heuristic_base_score": {
        "_note": "0 = neutral start (không bias). Prior dataset = 55.7% nhưng real-world thấp hơn",
        "recommended": 0,
        "rationale": "Start từ 0, chỉ cộng điểm khi có bằng chứng phishing"
    },
    "heuristic_rule_weights": {
        "_method": "Log-Likelihood Ratio (LLR) scaled to [0, 25]",
        "_formula": "W = log(P(feat=-1|phish) / P(feat=-1|legit)), scaled by max_LLR",
    },
    "confidence_weight_formula": {
        "_current": "min(1.0, model_confidence * 1.5) — hệ số 1.5 arbitrary",
        "_recommended": "model_confidence (plain, không nhân)",
        "_best_practice": "CalibratedClassifierCV (Platt scaling hoặc isotonic)",
        "_citation": "Niculescu-Mizil & Caruana (2005). Predicting Good Probabilities with Supervised Learning. ICML."
    }
}

for feat, pts in scaled.items():
    output["heuristic_rule_weights"][feat] = {
        "llr": round(llr_dict[feat], 4),
        "points": int(pts),
        "p_suspicious_given_phishing": round((phish[feat] == -1).sum() / N_phish, 4),
        "p_suspicious_given_legit":    round((legit[feat] == -1).sum() / N_legit, 4),
    }

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

print()
print("=" * 70)
print(f"Kết quả đã lưu vào: {OUTPUT_PATH}")
print("=" * 70)
