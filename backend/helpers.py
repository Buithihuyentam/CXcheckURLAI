from urllib.parse import urlparse
import re
from textblob import TextBlob
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
import pickle
import joblib
import re
import requests

# GET THE DOMAIN NAME FROM THE URL
def get_domain_name(url: str) -> str:
    if not url.startswith('http'):
        url = 'http://' + url
    parsed_url = urlparse(url)
    domain_name = "{uri.netloc}".format(uri=parsed_url)
    return domain_name

def check_google_batch(urls, api_key):
    # urls là một danh sách các link ['url1', 'url2', ...]
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    # Chuẩn bị danh sách entries
    threat_entries = [{"url": u} for u in urls]
    
    payload = {
        "client": {"clientId": "phishing-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries
        }
    }
    
    # Gọi API 1 lần duy nhất cho cả danh sách
    try:
        response = requests.post(api_url, json=payload, timeout=10)
        matches = response.json().get('matches', [])
        
        # Tạo danh sách kết quả (URL nào bị đánh dấu là độc hại)
        malicious_urls = [m['threat']['url'] for m in matches]
        return malicious_urls
    except:
        return []

# LOAD THE MODEL AND VECTORIZER for phishing
# phish_model = open('MLModels\\' + 'phishing_nlp.pkl','rb')
# phish_model_ls = joblib.load(phish_model)



# TEXT PREPROCESSING
sw = set(stopwords.words('english'))
