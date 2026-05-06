# predictor.py
import os
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

import httpx
import joblib
import pandas as pd
import whoisdomain
from bs4 import BeautifulSoup 
import asyncio


MODEL_PATH = os.path.join(os.path.dirname(__file__), "MLModels", "phishing_rf_model.pkl")
model = joblib.load(MODEL_PATH)
REQUIRED_FEATURES = model.feature_names_in_.tolist()

SHORTENER_DOMAINS = (
    r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|tiny\.cc|is\.gd|buff\.ly|adf\.ly|bitly\.com|shorturl\.at"
)


def _get_url_length(url):
    if len(url) < 54:
        return 1
    if len(url) <= 75:
        return 0
    return -1


def _external_ratio(url, items):
    if not items:
        return 0
    domain = urlparse(url).netloc.lower()
    external = 0
    for item in items:
        item_domain = urlparse(item).netloc.lower()
        if item_domain and item_domain != domain:
            external += 1
    return external / len(items)

def get_first_date(d):
     if isinstance(d, list): return d[0]
     return d
        
async def extract_features_async(url):
    print(f"\n[+] Đang phân tích trong model: {url}")
    features = {name: 0 for name in REQUIRED_FEATURES}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path or ""

    features['having_IPhaving_IP_Address'] = -1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 1
    features['URLURL_Length'] = _get_url_length(url)
    features['Shortining_Service'] = -1 if re.search(SHORTENER_DOMAINS, url) else 1
    features['having_At_Symbol'] = -1 if "@" in url else 1

    slash_index = url.find("//", url.find("://") + 3)
    features['double_slash_redirecting'] = -1 if slash_index != -1 else 1
    features['Prefix_Suffix'] = -1 if "-" in domain else 1
    features['having_Sub_Domain'] = -1 if domain.count('.') > 2 else 1
    features['SSLfinal_State'] = 1 if url.startswith('https://') else -1
    features['HTTPS_token'] = -1 if re.search(r'https[^/]', url.replace('https://', '').replace('http://', '')) else 1

    if parsed.port and parsed.port not in (80, 443):
        features['port'] = -1
    else:
        features['port'] = 1

    # OPTIMIZATION: Skip network call for shortened URLs (they'll be marked as warning anyway)
    is_shortener = features['Shortining_Service'] == -1
    if is_shortener:
        print(f"⚠️  Link rút gọn phát hiện - bỏ qua quá trình lấy nội dung (skip httpx)")
        # Set default safe values for features requiring network call
        features['Favicon'] = 1
        features['Request_URL'] = 1
        features['URL_of_Anchor'] = 1
        features['Links_in_tags'] = 1
        features['SFH'] = 1
        features['Submitting_to_email'] = 1
        features['Abnormal_URL'] = 0
        features['Redirect'] = 1
        features['on_mouseover'] = 1
        features['RightClick'] = 1
        features['popUpWidnow'] = 1
        features['Iframe'] = 1
        # Continue to WHOIS/DNS checks only
    else:
        # Only fetch page content for non-shortener URLs
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                response = await client.get(url)
                html = response.text
                soup = BeautifulSoup(html, 'html.parser')

                favicon = soup.find('link', rel=lambda value: value and 'icon' in value.lower())
                if favicon and favicon.get('href'):
                    favicon_url = favicon['href']
                    favicon_domain = urlparse(favicon_url).netloc.lower()
                    features['Favicon'] = -1 if favicon_domain and favicon_domain != domain else 1
                else:
                    features['Favicon'] = 1

                resources = []
                for tag in soup.find_all(['img', 'script', 'link']):
                    src = tag.get('src') or tag.get('href')
                    if src:
                        resources.append(src)
                features['Request_URL'] = -1 if _external_ratio(url, resources) > 0.5 else 1

                anchors = [a['href'] for a in soup.find_all('a', href=True)]
                anchor_ratio = _external_ratio(url, anchors)
                if anchor_ratio == 0:
                    features['URL_of_Anchor'] = 1
                elif anchor_ratio <= 0.31:
                    features['URL_of_Anchor'] = 1
                elif anchor_ratio <= 0.67:
                    features['URL_of_Anchor'] = 0
                else:
                    features['URL_of_Anchor'] = -1

                tags = [tag for tag in soup.find_all(['a', 'img', 'link', 'script'])]
                features['Links_in_tags'] = -1 if _external_ratio(url, [tag.get('href') or tag.get('src') for tag in tags if tag.get('href') or tag.get('src')]) > 0.5 else 1

                forms = soup.find_all('form', action=True)
                features['SFH'] = 1
                for form in forms:
                    action = form.get('action', '')
                    if action == '' or action == 'about:blank':
                        features['SFH'] = -1
                        break
                    if urlparse(action).netloc and urlparse(action).netloc.lower() != domain:
                        features['SFH'] = 0
                        break

                features['Submitting_to_email'] = -1 if any('mailto:' in form.get('action', '').lower() for form in forms) else 1
                features['Abnormal_URL'] = -1 if domain not in path else 0
                features['Redirect'] = -1 if len(response.history) > 1 else 1
                features['on_mouseover'] = -1 if 'onmouseover' in html.lower() else 1
                features['RightClick'] = -1 if 'oncontextmenu' in html.lower() else 1
                features['popUpWidnow'] = -1 if 'window.open' in html.lower() or 'alert(' in html.lower() else 1
                features['Iframe'] = -1 if soup.find('iframe') else 1
        except Exception:
            features['Favicon'] = features.get('Favicon', 1)
            features['Request_URL'] = features.get('Request_URL', 1)
            features['URL_of_Anchor'] = features.get('URL_of_Anchor', 1)
            features['Links_in_tags'] = features.get('Links_in_tags', 1)
            features['SFH'] = features.get('SFH', 1)
            features['Submitting_to_email'] = features.get('Submitting_to_email', 1)
            features['Abnormal_URL'] = features.get('Abnormal_URL', 0)
            features['Redirect'] = features.get('Redirect', 1)
            features['on_mouseover'] = features.get('on_mouseover', 1)
            features['RightClick'] = features.get('RightClick', 1)
            features['popUpWidnow'] = features.get('popUpWidnow', 1)
            features['Iframe'] = features.get('Iframe', 1)


    try:
        w = whoisdomain.query(domain)
        features["country"] = getattr(w, 'registrant_country', "Unknown")
        features["org"] = getattr(w, 'registrar', "Unknown")
        creation_date = get_first_date(w.creation_date)
        expiration_date = get_first_date(w.expiration_date)
        now = datetime.now()
        if creation_date and expiration_date:
            # FIX LOGIC 1: Registration Length = (Hết hạn - Hiện tại)
            # Theo chuẩn: Nếu thời gian còn lại < 1 năm (365 ngày) -> -1
            remaining_days = (expiration_date - now).days
            features['Domain_registeration_length'] = 1 if remaining_days > 365 else -1
            
            # FIX LOGIC 2: Age of Domain = (Hiện tại - Ngày tạo)
            # Theo chuẩn: Nếu tuổi đời >= 6 tháng (182 ngày) -> 1 (An toàn)
            age_days = (now - creation_date).days
            features['age_of_domain'] = 1 if age_days >= 182 else -1
        else:
            # Nếu không lấy được ngày, thường là link rác hoặc domain ẩn thông tin
            features['Domain_registeration_length'] = -1
            features['age_of_domain'] = -1
    except Exception:
        features['Domain_registeration_length'] = -1
        features['age_of_domain'] = -1

    try:
        socket.gethostbyname(domain)
        features['DNSRecord'] = 1
    except Exception:
        features['DNSRecord'] = -1

    return features

def get_risk_report(url, features_dict):
    input_df = pd.DataFrame([[features_dict[name] for name in REQUIRED_FEATURES]], columns=REQUIRED_FEATURES)
    prediction = model.predict(input_df)[0]
    prob = model.predict_proba(input_df)[0] if hasattr(model, 'predict_proba') else None
    confidence = max(prob) * 100 if prob is not None else 0
    score = confidence if prediction == 1 else (100 - confidence) if prob is not None else 0
    
    red_flags = []
    
    # Special handling: Shortener URLs are ALWAYS suspicious
    # Penalize score if it's a shortener
    is_shortener = features_dict.get('Shortining_Service') == -1
    if is_shortener:
        red_flags.append("Link được rút gọn (bit.ly, tinyurl...) - cần xác minh")
        # Penalize the score by 25 points for shorteners
        score = max(0, score - 25)
    
    if features_dict.get('SSLfinal_State') == -1:
        red_flags.append("Không có chứng chỉ bảo mật HTTPS")
    if features_dict.get('Prefix_Suffix') == -1:
        red_flags.append("Tên miền có chứa dấu gạch ngang nghi vấn")
    if features_dict.get('age_of_domain') == -1:
        red_flags.append("Tên miền mới đăng ký (tuổi đời thấp)")
    if features_dict.get('having_Sub_Domain') == -1:
        red_flags.append("Sử dụng quá nhiều tên miền phụ (subdomain)")
    
    # Phân loại mức độ
    # Special case: Shortener URLs are ALWAYS warning level
    if is_shortener:
        level = "NGHI NGỜ (CẢNH BÁO)"
        color = "Yellow"
    elif score >= 90:
        level = "TUYỆT ĐỐI AN TOÀN"
        color = "Green"
    elif score >= 70:
        level = "AN TOÀN"
        color = "Light Green"
    elif score >= 40:
        level = "NGHI NGỜ (CẢNH BÁO)"
        color = "Yellow"
    elif score >= 20:
        level = "NGUY HIỂM"
        color = "Orange"
    else:
        level = "CỰC KỲ NGUY HIỂM"
        color = "Red"
    return {
            "score": round(score, 2),
            "is_phishing": bool(prediction != 1),
            "red_flags": red_flags,
            "level": level,
            "color": color
    }

    
    
    
    
   

# --- HÀM CHẠY THỬ NGHIỆM (MAIN) ---
async def main():
    # 1. Danh sách các URL bạn muốn kiểm tra thử
    test_urls = [
        "https://www.google.com",                          # Web an toàn (Level 1-2)
        "https://bit.ly/4cNp5bV", # Web lừa đảo giả mạo (Level 4-5)
        "https://smartbanking.bidv.com.vn/dang-nhap",      # Web ngân hàng thật (Level 2-3)
        "http://skimfastplastering.com/e11acc076b4c98c6614eacae410859cf/verify.php"              # Web lừa đảo lộ liễu (Level 5)
    ]

    print("="*50)
    print("HỆ THỐNG PHÂN TÍCH RỦI RO URL")
    print("="*50)

    for url in test_urls:
        print(f"\n[+] Đang phân tích: {url}")
        
        try:
            # BƯỚC 1: Gọi hàm trích xuất đặc trưng (Sử dụng hàm async)
            # Đây là bước quan trọng nhất để "nạp đạn" cho mô hình
            features = await extract_features_async(url)

            # BƯỚC 2: Đưa bộ đặc trưng vào mô hình AI để lấy báo cáo
            report = get_risk_report(url, features)

            # BƯỚC 3: Hiển thị kết quả ra màn hình
            print(f"    - Mức độ: {report['level']}")
            print(f"    - Điểm an toàn: {report['score']}%")
            print(f"    - Cảnh báo lừa đảo: {'CÓ' if report['is_phishing'] else 'KHÔNG'}")
            
            if report['red_flags']:
                print(f"    - Các dấu hiệu nghi vấn:")
                for flag in report['red_flags']:
                    print(f"        [!] {flag}")
            else:
                print(f"    - Dấu hiệu: Tên miền có độ tin cậy cao.")

        except Exception as e:
            print(f"    - [!] Lỗi khi xử lý URL này: {e}")

# Lệnh khởi chạy chương trình
if __name__ == "__main__":
    # Khởi tạo vòng lặp sự kiện để chạy hàm async
    asyncio.run(main())