import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
import re
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
import socket
import warnings

# Tắt các cảnh báo không cần thiết
warnings.filterwarnings("ignore", category=UserWarning)

# =========================================================
# 1. TẢI MÔ HÌNH VÀ LẤY TÊN CỘT CHUẨN
# =========================================================
MODEL_PATH = '../MLModels/phishing_rf_model.pkl'

try:
    model = joblib.load(MODEL_PATH)
    # TỰ ĐỘNG LẤY DANH SÁCH TÊN CỘT MÀ MÔ HÌNH YÊU CẦU
    if hasattr(model, 'feature_names_in_'):
        REQUIRED_FEATURES = model.feature_names_in_.tolist()
    else:
        # Nếu model không lưu tên cột, dùng danh sách mặc định của bộ dữ liệu Kaggle
        REQUIRED_FEATURES = [
            'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service', 'having_At_Symbol', 
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State', 
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL', 
            'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 
            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 
            'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 
            'Statistical_report'
        ]
    print(f"--- Đã nạp mô hình. Mô hình yêu cầu {len(REQUIRED_FEATURES)} đặc trưng ---")
except Exception as e:
    print(f"Lỗi nạp mô hình: {e}")
    exit()

# =========================================================
# 2. HÀM TRÍCH XUẤT ĐẶC TRƯNG (ÁNH XẠ VÀO TÊN CỘT MỚI)
# =========================================================
def extract_features(url):
    f = {}
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Gán giá trị mặc định là 1 (An toàn) cho tất cả
    for name in REQUIRED_FEATURES: f[name] = 1

    # Trích xuất các đặc trưng cơ bản (Map đúng tên cột lạ)
    # 1. having_IP
    ip_p = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    f['having_IPhaving_IP_Address'] = -1 if re.search(ip_p, url) else 1
    
    # 2. URL_Length
    if len(url) < 54: f['URLURL_Length'] = 1
    elif 54 <= len(url) <= 75: f['URLURL_Length'] = 0
    else: f['URLURL_Length'] = -1
    
    # 3. Prefix_Suffix
    f['Prefix_Suffix'] = -1 if '-' in domain else 1
    
    # 4. SSLfinal_State
    f['SSLfinal_State'] = 1 if url.startswith('https') else -1

    # 5. having_Sub_Domain
    dots = domain.count('.')
    if dots <= 2: f['having_Sub_Domain'] = 1
    elif dots == 3: f['having_Sub_Domain'] = 0
    else: f['having_Sub_Domain'] = -1

    # Các đặc trưng mạng/nội dung (Rút gọn để chạy nhanh)
    try:
        res = requests.get(url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(res.text, 'html.parser')
        
        # URL_of_Anchor
        anchors = soup.find_all('a', href=True)
        unsafe = sum(1 for a in anchors if domain not in a['href'] and a['href'].startswith('http'))
        per = (unsafe / len(anchors)) * 100 if anchors else 0
        f['URL_of_Anchor'] = 1 if per < 31 else (0 if 31 <= per <= 67 else -1)
        
        # SFH
        f['SFH'] = -1 if any(form.get('action') == "" for form in soup.find_all('form')) else 1
    except:
        f['URL_of_Anchor'] = -1
        f['SFH'] = -1

    # WHOIS
    try:
        w = whois.whois(domain)
        start = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        age = (datetime.now() - start).days
        f['age_of_domain'] = 1 if age >= 182 else -1
    except:
        f['age_of_domain'] = -1

    return f

# =========================================================
# 3. HÀM DỰ ĐOÁN CHUẨN
# =========================================================
def predict_url(url):
    data_dict = extract_features(url)
    
    # Tạo danh sách giá trị theo đúng thứ tự REQUIRED_FEATURES
    ordered_values = [data_dict[name] for name in REQUIRED_FEATURES]
    
    # Tạo DataFrame để khớp tên cột hoàn toàn với mô hình
    input_df = pd.DataFrame([ordered_values], columns=REQUIRED_FEATURES)
    
    # Thực hiện dự đoán
    prediction = model.predict(input_df)[0]
    
    try:
        prob = model.predict_proba(input_df)[0]
        confidence = max(prob) * 100
    except:
        confidence = 100.0
        
    return prediction, confidence

def get_risk_report(url):
    # 1. Lấy kết quả từ AI và các đặc trưng đã trích xuất
    features_dict = extract_features(url) # Hàm trích xuất ở bài trước
    prediction, confidence = predict_url(url) # Hàm dự đoán ở bài trước
    
    # 2. Xác định mức độ dựa trên thang đo
    if prediction == 1: # AI bảo an toàn
        score = confidence
    else: # AI bảo nguy hiểm
        score = 100 - confidence

    # 3. Tổng hợp "Cơ sở" (Red Flags)
    red_flags = []
    if features_dict.get('SSLfinal_State') == -1:
        red_flags.append("Không có chứng chỉ bảo mật HTTPS")
    if features_dict.get('Prefix_Suffix') == -1:
        red_flags.append("Tên miền có chứa dấu gạch ngang nghi vấn")
    if features_dict.get('age_of_domain') == -1:
        red_flags.append("Tên miền mới đăng ký (tuổi đời thấp)")
    if features_dict.get('having_Sub_Domain') == -1:
        red_flags.append("Sử dụng quá nhiều tên miền phụ (subdomain)")

    # 4. Phân loại mức độ
    if score >= 90:
        level = "MỨC 1: TUYỆT ĐỐI AN TOÀN"
        color = "Green"
    elif score >= 70:
        level = "MỨC 2: AN TOÀN"
        color = "Light Green"
    elif score >= 40:
        level = "MỨC 3: NGHI NGỜ (CẢNH BÁO)"
        color = "Yellow"
    elif score >= 20:
        level = "MỨC 4: NGUY HIỂM"
        color = "Orange"
    else:
        level = "MỨC 5: CỰC KỲ NGUY HIỂM"
        color = "Red"

    return {
        "url": url,
        "score": round(score, 2),
        "level": level,
        "color": color,
        "red_flags": red_flags
    }

# --- TEST THỬ ---
report = get_risk_report("https://smartbanking.Bidv.com.vn/dang-nhap")
print(f"BÁO CÁO PHÂN TÍCH URL: {report['url']}")
print(f"Trạng thái: {report['level']} ({report['score']}%)")
print("Cơ sở xác định:")
for flag in report['red_flags']:
    print(f" - {flag}")