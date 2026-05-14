import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
import re
from urllib.parse import urlparse
import math
from Levenshtein import distance as lev

class ManualFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        # Danh sách các thương hiệu phổ biến để kiểm tra giả mạo (Brand Spoofing)
        self.brands = ['google', 'facebook', 'amazon', 'netflix', 'microsoft', 'apple', 'paypal', 'vcb', 'shopee']

    def fit(self, X, y=None):
        return self

    def get_entropy(self, text):
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p, 2) for p in prob])
        return entropy

    def extract_features(self, url):
        # Đảm bảo url là string và làm sạch khoảng trắng
        url = str(url).lower().strip()
        
        try:
            # Thử parse bình thường
            parsed = urlparse(url)
        except ValueError:
            # Nếu gặp lỗi "Invalid IPv6 URL" hoặc tương tự:
            # Loại bỏ dấu ngoặc vuông gây lỗi để có thể tiếp tục parse
            clean_url = url.replace("[", "").replace("]", "")
            try:
                parsed = urlparse(clean_url)
            except:
                # Nếu vẫn lỗi, tạo một object giả lập để không dừng chương trình
                from collections import namedtuple
                ParsedFallback = namedtuple('ParsedFallback', ['scheme', 'netloc', 'path'])
                parsed = ParsedFallback(scheme='', netloc='', path='')

        # 1. Chiều dài URL
        url_len = len(url)
        
        # 2. Kiểm tra HTTPS
        has_https = 1 if parsed.scheme == 'https' else 0
        
        # 3. Đếm số dấu chấm
        dot_count = url.count('.')
        
        # 4. Entropy (Độ gây nhiễu) - Xử lý an toàn nếu netloc rỗng
        domain_entropy = self.get_entropy(parsed.netloc) if parsed.netloc else 0
        
        # 5. Brand Spoofing
        brand_spoof = 0
        if parsed.netloc:
            parts = parsed.netloc.split('.')
            domain = parts[-2] if len(parts) >= 2 else parts[0]
            for b in self.brands:
                if 0 < lev(domain, b) <= 2:
                    brand_spoof = 1
                    break
        
        # 6. Có chứa IP thay vì domain?
        has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0

        return [url_len, has_https, dot_count, domain_entropy, brand_spoof, has_ip]
    
    def transform(self, X):
        features = [self.extract_features(url) for url in X]
        return np.array(features)