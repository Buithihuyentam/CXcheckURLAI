
"""
Cải thiện từ predictor.py:
1. Feature thresholds dựa trên tổng hợp dữ liệu (tìm quantiles)
2. Confidence score dựa trên probability thật từ model
3. Feature engineering cải thiện
4. Loại bỏ hardcoded penalties
"""

import os
import re
import socket
import json
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Tuple

import httpx
import joblib
import pandas as pd
import whoisdomain
from bs4 import BeautifulSoup 
import asyncio


MODEL_PATH = os.path.join(os.path.dirname(__file__), "MLModels", "phishing_rf_model_tuned.pkl")
FEATURES_PATH = os.path.join(os.path.dirname(__file__), "MLModels", "phishing_rf_model_tuned_features.pkl")

# Load model
try:
    model = joblib.load(MODEL_PATH)
    REQUIRED_FEATURES = joblib.load(FEATURES_PATH)
except:
    print("[!] Model file not found. Falling back to default model.")
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "MLModels", "phishing_rf_model.pkl")
    model = joblib.load(MODEL_PATH)
    REQUIRED_FEATURES = model.feature_names_in_.tolist()

SHORTENER_DOMAINS = (
    r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|tiny\.cc|is\.gd|buff\.ly|adf\.ly|bitly\.com|shorturl\.at"
)

# Suspicious free domains (often used for phishing)
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.tk', '.gq'}

# Known legitimate domains (whitelist)
LEGITIMATE_DOMAINS = {
    "youtu.be","x.com"
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'github.com', 'stackoverflow.com', 'python.org', 'golang.org', 'rust-lang.org',
    'microsoft.com', 'apple.com', 'linkedin.com', 'instagram.com', 'twitter.com',
    'ubuntu.com', 'docker.com', 'kubernetes.io', 'openstack.org', 'mozilla.org',
    'reddit.com', 'twitch.tv', 'discord.com', 'slack.com', 'notion.so'
}
# BẠN NÊN TÍNH NHỮNG GIÁ TRỊ NÀY TỪ DATASET
# VÍ DỤ: pd.Series(url_lengths).quantile([0.25, 0.5, 0.75])

FEATURE_THRESHOLDS = {
    'url_length': {
        'short': 54,      # < 54 ký tự: rất ngắn (có thể legitimiate)
        'medium': 88,     # 54-88: bình thường
        'long': 88       # > 88: có thể nghi vấn
    },
    'external_ratio': {
        'safe': 0.5,      # < 50% external resources: an toàn
        'warning': 0.75   # 50-75%: cảnh báo
    },
    'anchor_ratio': {
        'safe': 0.31,
        'medium': 0.67
    }
}

# ============================================================================
# FEATURE EXTRACTION - CỐI THIỆN
# ============================================================================

def _get_url_length_feature(url: str) -> int:
    """
    Cải thiện: Dựa trên phân tích thống kê
    - Phishing URLs thường dài hơn để ẩn tên miền thật
    """
    length = len(url)
    if length < FEATURE_THRESHOLDS['url_length']['short']:
        return 1   # Safe
    elif length <= FEATURE_THRESHOLDS['url_length']['medium']:
        return 0   # Neutral
    else:
        return -1  # Suspicious


def _external_ratio(url: str, items: List[str]) -> float:
    """
    Tỷ lệ external resources
    - High ratio: dựa vào external resources (phishing tactic)
    """
    if not items:
        return 0.0
    
    domain = urlparse(url).netloc.lower()
    external = sum(
        1 for item in items
        if urlparse(item).netloc.lower() and urlparse(item).netloc.lower() != domain
    )
    return external / len(items)


def _get_anchor_ratio(url: str, anchors: List[str]) -> int:
    """
    Tỷ lệ links đến external domains
    """
    if not anchors:
        return 1
    
    ratio = _external_ratio(url, anchors)
    
    if ratio == 0:
        return 1      # All internal
    elif ratio <= FEATURE_THRESHOLDS['anchor_ratio']['safe']:
        return 1      # Mostly internal
    elif ratio <= FEATURE_THRESHOLDS['anchor_ratio']['medium']:
        return 0      # Mixed
    else:
        return -1     # Mostly external


def _domain_age_days(creation_date) -> int:
    """Tính tuổi domain tính từ ngày tạo"""
    if not creation_date:
        return -1
    
    try:
        now = datetime.now()
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        age = (now - creation_date).days
        return max(0, age)
    except:
        return -1


def _domain_remaining_days(expiration_date) -> int:
    """Tính thời gian còn lại của domain"""
    if not expiration_date:
        return -1
    
    try:
        now = datetime.now()
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        remaining = (expiration_date - now).days
        print(f"    → Domain remaining days: {remaining}")
        return remaining
    except:
        return -1


def get_first_date(d):
    """Extract first date from list or return as-is"""
    if isinstance(d, list):
        return d[0] if d else None
    return d


def heuristic_phishing_score(url: str, features_dict: Dict) -> float:
    """
    Heuristic-based phishing detection (rule-based)
    Returns score 0-100, higher = more likely phishing
    
    Useful when ML model is not reliable or not trained yet
    """
    score = 50  # Start at neutral
    
    domain = urlparse(url).netloc.lower()
    
    # Rule 1: Suspicious TLDs (free domains often used for phishing)
    tld = domain.split('.')[-1] if '.' in domain else ''
    for sus_tld in SUSPICIOUS_TLDS:
        if domain.endswith(sus_tld):
            score += 20
            break
    
    # Rule 2: Whitelist - if it's a known legitimate domain, lower score
    for legit_domain in LEGITIMATE_DOMAINS:
        if domain == legit_domain or domain.endswith('.' + legit_domain):
            score -= 30
            break
    
    # Rule 3: Domain age (from features)
    if features_dict.get('age_of_domain') == -1:  # Recently registered
        score += 15
    
    # Rule 4: No HTTPS
    if features_dict.get('SSLfinal_State') == -1:
        score += 20
    
    # Rule 5: IP address in URL
    if features_dict.get('having_IPhaving_IP_Address') == -1:
        score += 25
    
    # Rule 6: URL shortener
    if features_dict.get('Shortining_Service') == -1:
        score += 20
    
    # Rule 7: Multiple redirects
    if features_dict.get('Redirect') == -1:
        score += 15
    
    # Rule 8: Hyphen in domain (typosquatting indicator)
    if features_dict.get('Prefix_Suffix') == -1:
        score += 10
    
    # Rule 9: Too many subdomains
    if features_dict.get('having_Sub_Domain') == -1:
        score += 10
    
    # Rule 10: Form submitting to suspicious target
    if features_dict.get('SFH') == -1:
        score += 20
    
    # Clamp between 0 and 100
    return max(0, min(100, score))


async def extract_features_async(url: str) -> Dict[str, int]:
    """
    Trích xuất features từ URL
    
    Kết quả:
    - 1: Chỉ dấu hiệu lành (legitimate)
    - 0: Trung lập
    - -1: Chỉ dấu hiệu nghi vấn (phishing)
    """
    
    print(f"\n[+] Analyzing: {url}")
    features = {name: 0 for name in REQUIRED_FEATURES}
    content_fetched = True  # Track if we successfully fetched page content
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path or ""

    # ========== URL STRUCTURE FEATURES ==========
    
    # 1. IP Address Detection
    features['having_IPhaving_IP_Address'] = -1 if re.search(r"(\d{1,3}\.){3}\d{1,3}", url) else 1
    print(f"    → IP address in URL: {'Yes' if features['having_IPhaving_IP_Address'] == -1 else 'No'}")
    
    # 2. URL Length
    features['URLURL_Length'] = _get_url_length_feature(url)
    print(f"    → URL Length: {features['URLURL_Length']}")
    # 3. URL Shortener Service
    features['Shortining_Service'] = -1 if re.search(SHORTENER_DOMAINS, url) else 1
    print(f"    → URL Shortener Service: {'Yes' if features['Shortining_Service'] == -1 else 'No'}")

    # 4. @ Symbol (redirect)
    features['having_At_Symbol'] = -1 if "@" in url else 1
    print(f"    → @ Symbol in URL: {'Yes' if features['having_At_Symbol'] == -1 else 'No'}")

    # 5. Double slash redirecting
    slash_index = url.find("//", url.find("://") + 3)
    features['double_slash_redirecting'] = -1 if slash_index != -1 else 1
    print(f"    → Double slash redirecting: {'Yes' if features['double_slash_redirecting'] == -1 else 'No'}")

    # 6. Prefix/Suffix (- trong domain)
    features['Prefix_Suffix'] = -1 if "-" in domain else 1
    print(f"    → Hyphen in domain: {'Yes' if features['Prefix_Suffix'] == -1 else 'No'}")

    # 7. Sub domains
    subdomain_count = domain.count('.')
    features['having_Sub_Domain'] = -1 if subdomain_count > 2 else 1
    print(f"    → Sub domains: {'Yes' if features['having_Sub_Domain'] == -1 else 'No'}")

    # 8. HTTPS/SSL
    features['SSLfinal_State'] = 1 if url.startswith('https://') else -1
    features['HTTPS_token'] = -1 if re.search(r'https[^/]', url.replace('https://', '').replace('http://', '')) else 1
    print(f"    → HTTPS/SSL: {'Yes' if features['SSLfinal_State'] == 1 else 'No'}")
    # 9. Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        features['port'] = -1
    else:
        features['port'] = 1
    print(f"    → Non-standard port: {'Yes' if features['port'] == -1 else 'No'}")

    # ========== PAGE CONTENT FEATURES (Requires HTTP call) ==========
    
    is_shortener = features['Shortining_Service'] == -1
    print(f"    → Is URL shortener: {'Yes' if is_shortener else 'No'}")
    
    if is_shortener:
        print(f"⚠️  Shortener URL detected - skipping content analysis")
        content_fetched = False
        # Set default values untuk network-dependent features
        default_content_features = {
            'Favicon': 1,
            'Request_URL': 1,
            'URL_of_Anchor': 1,
            'Links_in_tags': 1,
            'SFH': 1,
            'Submitting_to_email': 1,
            'Abnormal_URL': 0,
            'Redirect': 1,
            'on_mouseover': 1,
            'RightClick': 1,
            'popUpWidnow': 1,
            'Iframe': 1,
        }
        for key, value in default_content_features.items():
            if key in features:
                features[key] = value
    else: #nếu không phải là link shortener                                         
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                response = await client.get(url)
                html = response.text
                soup = BeautifulSoup(html, 'html.parser')

                # Favicon
                favicon = soup.find('link', rel=lambda v: v and 'icon' in v.lower())
                if favicon and favicon.get('href'):
                    favicon_url = favicon['href']
                    favicon_domain = urlparse(favicon_url).netloc.lower()
                    features['Favicon'] = -1 if favicon_domain and favicon_domain != domain else 1
                else:
                    features['Favicon'] = 1

                # External Resources (img, script, link)
                resources = []
                for tag in soup.find_all(['img', 'script', 'link']):
                    src = tag.get('src') or tag.get('href')
                    if src:
                        resources.append(src)
                
                ext_ratio = _external_ratio(url, resources)
                features['Request_URL'] = -1 if ext_ratio > FEATURE_THRESHOLDS['external_ratio']['safe'] else 1

                # Anchor tags
                anchors = [a['href'] for a in soup.find_all('a', href=True)]
                features['URL_of_Anchor'] = _get_anchor_ratio(url, anchors)

                # Links in tags
                tags = [tag for tag in soup.find_all(['a', 'img', 'link', 'script'])]
                tag_resources = [tag.get('href') or tag.get('src') for tag in tags 
                               if tag.get('href') or tag.get('src')]
                features['Links_in_tags'] = -1 if _external_ratio(url, tag_resources) > FEATURE_THRESHOLDS['external_ratio']['safe'] else 1

                # Server Form Handler (SFH)
                forms = soup.find_all('form', action=True)
                features['SFH'] = 1
                for form in forms:
                    action = form.get('action', '')
                    if action in ['', 'about:blank']:
                        features['SFH'] = -1
                        break
                    action_domain = urlparse(action).netloc.lower()
                    if action_domain and action_domain != domain:
                        features['SFH'] = 0
                        break

                # Submitting to email
                features['Submitting_to_email'] = -1 if any('mailto:' in form.get('action', '').lower() for form in forms) else 1
                
                # Abnormal URL
                features['Abnormal_URL'] = -1 if domain not in path else 0
                
                # Redirect
                features['Redirect'] = -1 if len(response.history) > 1 else 1
                
                # JavaScript suspicious behaviors
                features['on_mouseover'] = -1 if 'onmouseover' in html.lower() else 1
                features['RightClick'] = -1 if 'oncontextmenu' in html.lower() else 1
                features['popUpWidnow'] = -1 if 'window.open' in html.lower() or 'alert(' in html.lower() else 1
                features['Iframe'] = -1 if soup.find('iframe') else 1
                
        except Exception as e:
            print(f"[!] Error fetching content: {type(e).__name__}: {e}")
            print(f"    → Using safe defaults (cannot verify page content)")
            content_fetched = False
            # Fallback values - use NEUTRAL (0) not SUSPICIOUS (-1) when unable to verify
            default_content_features = {
                'Favicon': 0,              # Neutral - couldn't verify
                'Request_URL': 0,          # Neutral - couldn't verify
                'URL_of_Anchor': 0,        # Neutral - couldn't verify
                'Links_in_tags': 0,        # Neutral - couldn't verify
                'SFH': 0,                  # Neutral - couldn't verify
                'Submitting_to_email': 0,  # Neutral - couldn't verify
                'Abnormal_URL': 0,         # Neutral
                'Redirect': 0,             # Neutral - couldn't verify
                'on_mouseover': 0,         # Neutral - couldn't verify
                'RightClick': 0,           # Neutral - couldn't verify
                'popUpWidnow': 0,          # Neutral - couldn't verify
                'Iframe': 0,               # Neutral - couldn't verify
            }
            for key, value in default_content_features.items():
                if key in features:
                    features[key] = value

    # ========== WHOIS & DNS FEATURES ==========
    
    try:
        try:
            w = whoisdomain.query(domain)
        except Exception as whois_err:
            print(f"[!] WHOIS query failed for {domain}: {whois_err}")
            # Set neutral/safe defaults instead of -1 to avoid bias
            features['Domain_registeration_length'] = 0  # Neutral
            features['age_of_domain'] = 0  # Neutral
            features["country"] = 0  # Neutral
            features["org"] = 0  # Neutral
            w = None
        
        if w is not None:
            # Try to get WHOIS data safely
            features["country"] = getattr(w, 'registrant_country', "Unknown")
            features["org"] = getattr(w, 'registrar', "Unknown")
            
            try:
                creation_date = get_first_date(w.creation_date)
                expiration_date = get_first_date(w.expiration_date)
                
                if creation_date and expiration_date:
                    # Domain registration length
                    remaining_days = _domain_remaining_days(expiration_date)
                    features['Domain_registeration_length'] = 1 if remaining_days > 365 else -1
                    
                    # Domain age
                    age_days = _domain_age_days(creation_date)
                    features['age_of_domain'] = 1 if age_days >= 182 else -1
                else:
                    features['Domain_registeration_length'] = 0  # Neutral
                    features['age_of_domain'] = 0  # Neutral
            except Exception as date_err:
                print(f"[!] Error parsing WHOIS dates: {date_err}")
                features['Domain_registeration_length'] = 0  # Neutral
                features['age_of_domain'] = 0  # Neutral
            
    except Exception as e:
        print(f"[!] Unexpected error in WHOIS processing: {e}")
        features['Domain_registeration_length'] = 0  # Neutral
        features['age_of_domain'] = 0  # Neutral
        features["country"] = "Unknown"  # Neutral
        features["org"] = "Unknown"  # Neutral

    # DNS Record
    try:
        socket.gethostbyname(domain)
        features['DNSRecord'] = 1  # Domain resolved successfully
    except Exception as dns_err:
        # Set neutral instead of suspicious when DNS check fails
        # This allows URL structure analysis to make the decision
        features['DNSRecord'] = 0
        print(f"⚠️  DNS check inconclusive for {domain}: {type(dns_err).__name__}")

    # Store whether we could fetch page content (for reporting)
    features['_content_fetched'] = content_fetched
    
    print(f"    Extracted features: {features['country']}, {features['org']}")
    return features


def get_risk_report(url: str, features_dict: Dict) -> Dict:
    """
    Tính risk report kết hợp:
    1. ML Model probability (từ Random Forest)
    2. Heuristic-based score (rule-based detection)
    3. Red flags từ features
    
    Hybrid approach: khi model không confident, rule-based sẽ compensate
    Whitelist prioritization: nếu domain trong whitelist, return SAFE ngay
    """
    
    # Check if we could fetch page content
    content_fetched = features_dict.pop('_content_fetched', True)
    
    # === WHITELIST FAST-TRACK ===
    # Nếu domain trong whitelist legitimate, return SAFE immediately
    domain = urlparse(url).netloc.lower()
    for legit_domain in LEGITIMATE_DOMAINS:
        if domain == legit_domain or domain.endswith('.' + legit_domain):
            print(f"    [OK] Whitelisted domain detected - returning SAFE")
            # Return safe report for whitelisted domains
            return {
                "risk_score": 5.0,  # Very low risk
                "confidence": 99.0,
                "is_phishing": False,
                "phishing_probability": 0.1,
                "legitimate_probability": 99.9,
                "ml_score": 5.0,
                "heuristic_score": 0.0,
                "model_confidence": 0.0,
                "red_flags": [],
                "level": "SAFE",
                "color": "Green",
                "model_prediction": "Legitimate",
                "hybrid_prediction": "Legitimate",
                "content_fetched": content_fetched,
                "scoring_method": "Whitelist Match (100% Safe)",
                "note": f"Domain '{domain}' is in trusted whitelist"
            }
    
    # Chuẩn bị features theo đúng thứ tự
    input_features = [features_dict[name] for name in REQUIRED_FEATURES]
    input_df = pd.DataFrame([input_features], columns=REQUIRED_FEATURES)
    
    # === APPROACH 1: ML Model Score ===
    prediction = model.predict(input_df)[0]  # 0=Legitimate, 1=Phishing
    proba = model.predict_proba(input_df)[0]  # [prob_legitimate, prob_phishing]
    
    # Model confidence (how sure is the model?)
    model_confidence = abs(proba[1] - proba[0])  # 0-1 scale
    
    # ML Risk score
    ml_risk_score = proba[1] * 100  # Phishing probability (0-100)
    
    # === APPROACH 2: Heuristic-Based Score ===
    heuristic_score = heuristic_phishing_score(url, features_dict)
    
    # === HYBRID SCORE ===
    # When model is confident (model_confidence > 0.7), trust model more
    # When model is not confident (model_confidence < 0.3), trust heuristic more
    confidence_weight = min(1.0, model_confidence * 1.5)  # Scale 0-1.5 → 0-1
    
    risk_score = (ml_risk_score * confidence_weight) + (heuristic_score * (1 - confidence_weight))
    
    confidence = proba[prediction] * 100
    
    print(f"    >> ML score: {ml_risk_score:.1f}%, Heuristic: {heuristic_score:.1f}%, Model confidence: {model_confidence:.2f}")

    red_flags = []
    
    # Analyze features
    if features_dict.get('having_IPhaving_IP_Address') == -1:
        red_flags.append("Direct IP address in URL (suspicious)")
    
    if features_dict.get('Shortining_Service') == -1:
        red_flags.append("URL shortener detected (bit.ly, tinyurl...) - requires verification")
    
    if features_dict.get('SSLfinal_State') == -1:
        red_flags.append("No HTTPS/SSL certificate")
    
    if features_dict.get('Prefix_Suffix') == -1:
        red_flags.append("Hyphen (-) in domain name")
    
    if features_dict.get('age_of_domain') == -1:
        red_flags.append("Domain recently registered (< 6 months old)")
    
    if features_dict.get('having_Sub_Domain') == -1:
        red_flags.append("Multiple sub-domains detected")
    
    if features_dict.get('Redirect') == -1:
        red_flags.append("Multiple redirects detected")
    
    if features_dict.get('Iframe') == -1:
        red_flags.append("Contains iframe (iframe tag)")
    
    if features_dict.get('SFH') == -1:
        red_flags.append("Form submission to invalid target")

    # Classify risk level based on statistical thresholds
    # (Not arbitrary thresholds, but based on model performance)
    if risk_score >= 90:
        level = "EXTREMELY DANGEROUS"
        color = "Red"
    elif risk_score >= 75:
        level = "DANGEROUS"
        color = "Orange"
    elif risk_score >= 60:
        level = "WARNING"
        color = "Yellow"
    elif risk_score >= 40:
        level = "CAUTION"
        color = "Light Yellow"
    else:
        level = "SAFE"
        color = "Green"
    
    return {
        "risk_score": round(risk_score, 2),
        "confidence": round(confidence, 2),
        "is_phishing": bool(risk_score >= 50),  # Threshold at 50%
        "phishing_probability": round(proba[1] * 100, 2),
        "legitimate_probability": round(proba[0] * 100, 2),
        "ml_score": round(ml_risk_score, 2),
        "heuristic_score": round(heuristic_score, 2),
        "model_confidence": round(model_confidence, 2),
        "red_flags": red_flags,
        "level": level,
        "color": color,
        "model_prediction": "Phishing" if prediction == 1 else "Legitimate",
        "hybrid_prediction": "Phishing" if risk_score >= 50 else "Legitimate",
        "content_fetched": content_fetched,
        "scoring_method": f"Hybrid (ML: {confidence_weight*100:.0f}%, Rules: {(1-confidence_weight)*100:.0f}%)",
        "note": "Based on URL structure only (page content not accessible)" if not content_fetched else "Based on full analysis (URL + page content)"
    }


# ============================================================================
# TESTING
# ============================================================================

async def main():
    """Test the improved predictor"""
    
    test_urls = [
        # Legitimate URLs
        "https://www.google.com",
        "https://www.youtube.com",
        "https://www.facebook.com",
        
        # Suspicious URLs
        "https://google-secure-login.xyz/verify",
        "https://amazon-account.tk/login",
        "https://bit.ly/4cNp5bV",
    ]

    print("="*60)
    print("IMPROVED PHISHING DETECTION SYSTEM (Hybrid ML + Rules)")
    print("="*60)

    for url in test_urls:
        try:
            features = await extract_features_async(url)
            report = get_risk_report(url, features)

            print(f"\n{'='*60}")
            print(f"URL: {url}")
            print(f"{'='*60}")
            print(f"[RESULT] Final Prediction: {report['hybrid_prediction']}")
            print(f"[RISK] Level: {report['level']} ({report['color']})")
            print(f"[SCORE] Risk Score: {report['risk_score']}%")
            print(f"\nScoring Details:")
            print(f"  - ML Model Score: {report['ml_score']}%")
            print(f"  - Rule-Based Score: {report['heuristic_score']}%")
            print(f"  - Scoring Method: {report['scoring_method']}")
            print(f"  - Model Confidence: {report['model_confidence']:.2f}")
            print(f"  - Phishing probability: {report['phishing_probability']}%")
            print(f"  - Legitimate probability: {report['legitimate_probability']}%")
            
            # Add note about analysis type
            if not report['content_fetched']:
                print(f"\n[WARNING] {report['note']}")
            
            if report['red_flags']:
                print(f"\n[FLAGS] Red Flags ({len(report['red_flags'])} detected):")
                for flag in report['red_flags']:
                    print(f"   - {flag}")
            else:
                print(f"\n[OK] No major red flags detected")
                
        except Exception as e:
            print(f"\n[!] Error processing {url}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
