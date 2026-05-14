"""
Phishing URL Detection — Hybrid ML + Heuristic Predictor (v2.2)
===============================================================
Triển khai theo phương pháp Deployability-Driven Feature Selection.
Mô hình: XGBoost Calibrated trained on PhiUSIIL 2023 (Cleaned).
"""

import os
import re
import math
import socket
import json
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Optional

import httpx
import joblib
from bs4 import BeautifulSoup
import tldextract
from cachetools import TTLCache
import Levenshtein

_BASE_DIR = os.path.dirname(__file__)

# Load XGBoost calibrated model (v2.2)
_XGB_MODEL_PATH      = os.path.join(_BASE_DIR, "MLModels", "phishing_xgb_calibrated.pkl")
_XGB_FEATURES_PATH   = os.path.join(_BASE_DIR, "MLModels", "phishing_xgb_features.pkl")
_THRESHOLD_PATH      = os.path.join(_BASE_DIR, "MLModels", "optimal_threshold.json")

try:
    model = joblib.load(_XGB_MODEL_PATH)
    REQUIRED_FEATURES = joblib.load(_XGB_FEATURES_PATH)
    print(f"[OK] Loaded: XGBoost + Calibrated (PhiUSIIL Clean)")
except Exception as e:
    raise RuntimeError(f"[!] No model found: {e}. Please run train_model_final.py")

try:
    with open(_THRESHOLD_PATH) as f:
        _threshold_meta = json.load(f)
    OPTIMAL_THRESHOLD = _threshold_meta["optimal_threshold"]
    print(f"[OK] Optimal threshold: {OPTIMAL_THRESHOLD}")
except Exception:
    OPTIMAL_THRESHOLD = 0.5
    print("[!] optimal_threshold.json not found, using default 0.5")

# SHAP explainer
_shap_explainer = None
def _get_shap_explainer():
    global _shap_explainer
    if _shap_explainer is None:
        try:
            import shap
            if hasattr(model, 'calibrated_classifiers_'):
                base = model.calibrated_classifiers_[0].estimator
            else:
                base = model
            _shap_explainer = shap.TreeExplainer(base)
        except Exception as e:
            print(f"[!] SHAP init failed: {e}")
    return _shap_explainer

# Cache
_feature_cache: TTLCache = TTLCache(maxsize=500, ttl=3600)

# ============================================================================
# WHITELIST & RISK DICTIONARIES
# ============================================================================

LEGITIMATE_DOMAINS = {
    "youtu.be", "x.com", "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "github.com", "stackoverflow.com", "python.org", "microsoft.com",
    "apple.com", "linkedin.com", "instagram.com", "twitter.com", "reddit.com"
}

TOP_50_BRANDS = [
    "google", "facebook", "microsoft", "apple", "amazon", "netflix", "paypal",
    "instagram", "linkedin", "twitter", "yahoo", "whatsapp", "tiktok", "spotify"
]

SUSPICIOUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'xyz', 'gq', 'top', 'pw', 'online', 'site'}

def _get_registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ""

def _is_whitelisted(url: str) -> bool:
    return _get_registered_domain(url) in LEGITIMATE_DOMAINS

# ============================================================================
# FEATURE EXTRACTION (36 Features PhiUSIIL)
# ============================================================================

async def extract_features_async(url: str) -> Dict[str, float]:
    cache_key = url.lower().strip()
    if cache_key in _feature_cache:
        return _feature_cache[cache_key]

    features = {name: 0.0 for name in REQUIRED_FEATURES}
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path or ""
    ext = tldextract.extract(url)

    # 1. URL Lexical Features
    features['URLLength'] = len(url)
    features['DomainLength'] = len(domain)
    features['IsDomainIP'] = 1.0 if re.search(r"(\d{1,3}\.){3}\d{1,3}", domain) else 0.0
    features['TLDLength'] = len(ext.suffix) if ext.suffix else 0
    features['NoOfSubDomain'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
    
    # Obfuscation (rất cơ bản: kiểm tra URL encoded chars như %20)
    features['NoOfObfuscatedChar'] = url.count('%')
    features['HasObfuscation'] = 1.0 if features['NoOfObfuscatedChar'] > 0 else 0.0
    features['ObfuscationRatio'] = features['NoOfObfuscatedChar'] / max(1, len(url))
    
    # Chars distribution
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    features['NoOfLettersInURL'] = letters
    features['LetterRatioInURL'] = letters / max(1, len(url))
    features['NoOfDegitsInURL'] = digits
    features['DegitRatioInURL'] = digits / max(1, len(url))
    
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    
    special_chars = sum(not c.isalnum() for c in url)
    features['NoOfOtherSpecialCharsInURL'] = special_chars
    features['SpacialCharRatioInURL'] = special_chars / max(1, len(url))
    
    features['IsHTTPS'] = 1.0 if url.startswith('https://') else 0.0
    
    # Keywords
    url_lower = url.lower()
    features['Bank'] = 1.0 if 'bank' in url_lower else 0.0
    features['Pay'] = 1.0 if 'pay' in url_lower else 0.0
    features['Crypto'] = 1.0 if 'crypto' in url_lower or 'wallet' in url_lower else 0.0

    # 2. Page Content Features (Fetch <head> nhanh)
    # Default 0.0 (Neutral/False) neu khong fetch duoc
    features['HasTitle'] = 0.0
    features['HasFavicon'] = 0.0
    features['Robots'] = 0.0
    features['IsResponsive'] = 0.0
    features['NoOfURLRedirect'] = 0.0
    features['NoOfSelfRedirect'] = 0.0
    features['HasDescription'] = 0.0
    features['NoOfPopup'] = 0.0
    features['NoOfiFrame'] = 0.0
    features['HasExternalFormSubmit'] = 0.0
    features['HasSocialNet'] = 0.0
    features['HasSubmitButton'] = 0.0
    features['HasHiddenFields'] = 0.0
    features['HasPasswordField'] = 0.0
    features['HasCopyrightInfo'] = 0.0

    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=True,
                                     headers={"User-Agent": "Mozilla/5.0"}) as client:
            response = await client.get(url)
            html = response.text.lower()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            features['NoOfURLRedirect'] = len(response.history)
            
            if soup.title and soup.title.string:
                features['HasTitle'] = 1.0
            if soup.find('link', rel=lambda v: v and 'icon' in v.lower()):
                features['HasFavicon'] = 1.0
            if soup.find('meta', attrs={'name': 'robots'}):
                features['Robots'] = 1.0
            if soup.find('meta', attrs={'name': 'viewport'}):
                features['IsResponsive'] = 1.0
            if soup.find('meta', attrs={'name': 'description'}):
                features['HasDescription'] = 1.0
                
            features['NoOfPopup'] = 1.0 if 'window.open' in html or 'alert(' in html else 0.0
            features['NoOfiFrame'] = 1.0 if soup.find('iframe') else 0.0
            
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '').lower()
                if action and not action.startswith('/') and domain not in action:
                    features['HasExternalFormSubmit'] = 1.0
                    break
            
            socials = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']
            if any(s in html for s in socials):
                features['HasSocialNet'] = 1.0
                
            if soup.find('input', type='submit') or soup.find('button', type='submit'):
                features['HasSubmitButton'] = 1.0
            if soup.find('input', type='hidden'):
                features['HasHiddenFields'] = 1.0
            if soup.find('input', type='password'):
                features['HasPasswordField'] = 1.0
            if 'copyright' in html or '©' in html:
                features['HasCopyrightInfo'] = 1.0

    except Exception as e:
        print(f"[!] Error fetching {url}: {e} -> Using neutral content features")

    # Filter only required features to ensure exact match with model
    final_features = {k: float(features.get(k, 0.0)) for k in REQUIRED_FEATURES}
    _feature_cache[cache_key] = final_features
    return final_features


# ============================================================================
# HEURISTIC ENGINE (Real-time Engineering)
# ============================================================================

def heuristic_phishing_score(url: str, features_dict: Dict) -> float:
    """
    Heuristic engine cập nhật 2024 (Dựa trên recommendation):
    1. HTTP thuần = RED FLAG nặng (+40)
    2. Levenshtein Brand Distance (Typosquatting) = RED FLAG (+30)
    3. TLD rủi ro cao = RED FLAG (+20)
    """
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    ext = tldextract.extract(url)

    # 1. HTTP = Bad
    if features_dict.get('IsHTTPS', 1.0) == 0.0:
        score += 40

    # 2. Typosquatting (Levenshtein distance)
    # Neu domain gan giong brand noi tieng nhung khong phai brand do
    domain_name = ext.domain
    is_typo = False
    if domain_name not in TOP_50_BRANDS:  # Neu chinh la brand thi ok
        for brand in TOP_50_BRANDS:
            dist = Levenshtein.distance(domain_name, brand)
            if dist == 1 or (dist == 2 and len(brand) > 5):
                is_typo = True
                break
    if is_typo:
        score += 30

    # 3. Risky TLD
    if ext.suffix in SUSPICIOUS_TLDS:
        score += 20

    # 4. Shortener
    if re.search(r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co", domain):
        score += 20

    return min(100, score)


# ============================================================================
# RED FLAGS (SHAP-based Explanations)
# ============================================================================

def generate_red_flags(url: str, features_dict: Dict, model_proba: float) -> List[str]:
    flags = []
    
    # 1. Heuristic hard flags
    if features_dict.get('IsHTTPS', 1.0) == 0.0:
        flags.append("Trang web không sử dụng HTTPS (Rất nguy hiểm)")
    
    ext = tldextract.extract(url)
    if ext.suffix in SUSPICIOUS_TLDS:
        flags.append(f"Sử dụng tên miền cấp cao rủi ro (.{ext.suffix})")

    domain_name = ext.domain
    if domain_name not in TOP_50_BRANDS:
        for brand in TOP_50_BRANDS:
            dist = Levenshtein.distance(domain_name, brand)
            if dist == 1 or (dist == 2 and len(brand) > 5):
                flags.append(f"Tên miền nhái thương hiệu '{brand}' (Typosquatting)")
                break

    # 2. SHAP Model Explanations
    try:
        explainer = _get_shap_explainer()
        if explainer and model_proba >= OPTIMAL_THRESHOLD:
            import pandas as pd
            import numpy as np
            # Convert to correct shape
            df_single = pd.DataFrame([features_dict], columns=REQUIRED_FEATURES)
            sv = explainer.shap_values(df_single)
            
            # Extract SHAP values (handle different SHAP return types)
            if isinstance(sv, list):
                shap_vals = sv[1][0]
            elif len(sv.shape) == 3:
                shap_vals = sv[0, :, 1]
            else:
                shap_vals = sv[0]
                
            # Get top 2 features pushing score towards phishing
            top_indices = np.argsort(shap_vals)[-2:][::-1]
            for idx in top_indices:
                if shap_vals[idx] > 0.5: # Chi lay nhung feature dong gop dang ke
                    feat_name = REQUIRED_FEATURES[idx]
                    val = features_dict[feat_name]
                    
                    if feat_name == 'URLLength' and val > 75:
                        flags.append("Độ dài URL bất thường (cố tình che giấu)")
                    elif feat_name == 'IsDomainIP' and val == 1.0:
                        flags.append("Sử dụng địa chỉ IP thay vì tên miền")
                    elif feat_name == 'NoOfSubDomain' and val > 2:
                        flags.append("Có quá nhiều subdomains (đánh lừa người dùng)")
                    elif feat_name == 'HasPasswordField' and val == 1.0:
                        flags.append("Trang web yêu cầu mật khẩu không đáng tin")
    except Exception as e:
        print(f"[!] SHAP Error in red_flags: {e}")

    # Fallback default nếu không có cờ nào
    if not flags and model_proba >= OPTIMAL_THRESHOLD:
        flags.append("Cấu trúc URL có độ rủi ro cao")
        
    return list(dict.fromkeys(flags)) # Remove duplicates


# ============================================================================
# MAIN PREDICT FUNCTION
# ============================================================================

async def predict_phishing(url: str) -> Dict:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # 1. Whitelist Check
    if _is_whitelisted(url):
        return {
            "url": url,
            "phishing_probability": 0.0,
            "is_phishing": False,
            "heuristic_score": 0,
            "red_flags": [],
            "status": "success",
            "model_version": "Whitelist"
        }

    try:
        # 2. Extract Features
        features_dict = await extract_features_async(url)
        
        import pandas as pd
        df = pd.DataFrame([features_dict], columns=REQUIRED_FEATURES)

        # 3. Model Prediction
        y_proba = float(model.predict_proba(df)[0, 1])
        is_phish_ml = y_proba >= OPTIMAL_THRESHOLD

        # 4. Heuristic Prediction
        h_score = heuristic_phishing_score(url, features_dict)
        is_phish_h = h_score >= 60

        # 5. Hybrid Decision (OR logic for security)
        is_phishing = is_phish_ml or is_phish_h
        
        # 6. Explanations
        red_flags = generate_red_flags(url, features_dict, y_proba)

        return {
            "url": url,
            "phishing_probability": y_proba,
            "is_phishing": is_phishing,
            "heuristic_score": h_score,
            "red_flags": red_flags,
            "status": "success",
            "model_version": "v2.2 (PhiUSIIL Clean)"
        }

    except Exception as e:
        print(f"[!] Prediction error for {url}: {e}")
        return {
            "url": url,
            "error": str(e),
            "status": "error"
        }
