# Libraries and frameworks
import uvicorn
import httpx
from pydantic import BaseModel
from fastapi import FastAPI
import csv
import whoisdomain
import pycountry
from tortoise.contrib.fastapi import register_tortoise
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from typing import List
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor
import joblib
# Local files
from feature import ManualFeatureExtractor
from predictor_improved import get_risk_report, extract_features_async
from helpers import get_domain_name,check_google_batch
from models import PhishingReportSchema, reviewDetectionSchema, PhishingReport, newsDetectionSchema, mistakePhishingReport
# from debug_model

# Initialize FastAPI
app = FastAPI()

# Vì thư viện whoisdomain chạy đồng bộ (blocking), ta dùng ThreadPool để không làm treo server
executor = ThreadPoolExecutor(max_workers=10)
api_key="AIzaSyA8n9sXo2l7mLh0Zt1kKjv3X9z5y6w7x8"

# model = joblib.load("MLModels/phishing_nlp.pkl" )
# extractor = ManualFeatureExtractor()

async def get_original_url(short_url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Khởi tạo kết quả mặc định (trường hợp không tìm thấy meta)
    data = {
        "meta_url": short_url,
        "final_url": short_url
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, headers=headers) as client:
            # Bước 1: Gửi yêu cầu đến link t.co
            response = await client.get(short_url)
            
            # Kiểm tra Meta Refresh trong HTML
            html_content = response.text
            meta_match = re.search(r'content="0;URL=\'?(.*?)\'?"', html_content, re.IGNORECASE)
            
            if meta_match:
                # Bước 2: Bóc tách link Meta
                raw_meta_url = meta_match.group(1)
                meta_url = raw_meta_url.replace("&amp;", "&") 
                data["meta_url"] = meta_url # Lưu link meta để hiện lên popup
                
                print(f"🔗 Tìm thấy link Meta: {meta_url}")
                
                # Bước 3: TRUY CẬP TIẾP link này để lấy link xác thực cuối cùng
                final_response = await client.get(meta_url)
                data["final_url"] = str(final_response.url) # Link đích cuối cùng sau mọi redirect
                
                print(f"✅ Link xác thực cuối cùng: {data['final_url']}")
            else:
                # Nếu không có Meta Refresh, httpx đã tự đuổi theo đến cùng
                data["meta_url"] = str(response.url)
                data["final_url"] = str(response.url)

            return data

    except Exception as e:
        print(f"❌ Lỗi: {e}")
        return data # Trả về link gốc nếu gặp lỗi
class UrlList(BaseModel):
    urls: List[str]

# Connect to database
register_tortoise(
    app,
    db_url="sqlite://db/db.sqlite3",
    modules={"models": ["models"]},
    generate_schemas=True,
    add_exception_handlers=True
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],
)
# API root
@app.get('/')
async def index():
    return {
        "GET": {
            "/phishing": "Takes a URL as a parameter and returns True if the website is phishing, False if it is not.",
            "/reports": "Returns all the reports the users have reported.",
            "/details": "Takes a URL as a parameter and returns details about the domain such as name, registrar, registrant country, creation date, expiration date, last updated, dnssec, registrant, emails, and country name.",
            "/analyze": "COMBINED ENDPOINT: Takes a URL and returns both phishing prediction AND domain details in one request."
        },
            "POST": {
            "/report": {
                "description": "Takes a URL and a reason as parameters and reports a website. Returns 'already reported' if the website has already been reported, 'invalid url' if the URL is invalid, and 'success' if the report was successful.",
                "format": {
                    "url": "www.example.com",
                    "Reason": "very bad example."
                }
            },
        },
        "PUT": {
            "/reports/{id}": {
                "description": "Takes an id and a boolean value as parameters and sets the validity of the report. Returns 'success' if the operation was successful, 'failed' if it was not.",
                "format": "/reports/{id}?real={true || false}"
            }
        }
    }


# report phishing and save to database
@app.post('/report')
async def report(report: PhishingReportSchema):
    domain = get_domain_name(report.url)
    reports = await PhishingReport.all()
    urls = [report.url for report in reports]
    if domain in urls:
        return {'result': 'already reported'}
    elif not domain:
        return {'result': 'invalid url'}
    report = PhishingReport(url=domain, reason=report.reason)
    await report.save()
    return {'result': 'success'}


# report mistake phishing and save to database
@app.post('/report_mistake')
async def report_mistake(report: PhishingReportSchema):
    domain = get_domain_name(report.url)
    reports = await mistakePhishingReport.all()
    urls = [report.url for report in reports]
    if domain in urls:
        return {'result': 'already reported'}
    elif not domain:
        return {'result': 'invalid url'}
    report = mistakePhishingReport(url=domain, reason=report.reason, real=True)
    await report.save()
    return {'result': 'success'}


#get all reports
@app.get('/reports')
async def reports():
    reports = await PhishingReport.all()
    return reports

#update report
@app.put('/report/{id}')
async def update(id: int, real: bool):
    try:
        await PhishingReport.filter(id=id).update(real=real)
        if real:
            with open('Datasets/phishing_site_urls.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(str(PhishingReport.get(id=id).url),"bad")
        return {'result': 'success'}
    except:
        return {'result': 'failed'}


# check single link and return both phishing prediction and domain details when bôi đen link
@app.get("/analyze")
async def analyze_link(url: str):
    domain = get_domain_name(url)
    if not domain:
        return {"error": "Invalid URL", "is_phishing": True, "details": None}

    features = await extract_features_async(url)
    report = get_risk_report(url, features)
    score = report["confidence"]  # Điểm xác suất lừa đảo từ 0 đến 1
    print(f"Kêt quả dự đoán trong analyze: ")
    print(f"    - Mức độ: {report['level']}")
    print(f"    - Điểm an toàn: {score}%")
    print(f"    - Cảnh báo lừa đảo: {'CÓ' if report['is_phishing'] else 'KHÔNG'}")
    
    is_in_db = await PhishingReport.filter(url=domain, real=True).exists()
    
    is_phishing = report["is_phishing"] or is_in_db

    # --- 2. Lấy thông tin chi tiết từ features đã trích xuất 
    details = {
        "domain": domain,
        "country": features.get("country", "Unknown"),
        "org": features.get("org", "Unknown"), 
        "level": report["level"],
        "risk_score": score,
    }

    # --- 3. Trả về kết quả tổng hợp ---
    return {
        "url": url,
        "is_phishing": bool(is_phishing), # Chuyển về kiểu boolean thật (True/False)
        "details": details
    }
    
       
async def process_single_url(url):
    """Hàm xử lý tách biệt cho từng link"""
    try:
        # 1. Giải mã link rút gọn (Hàm httpx của bạn đã là async nên rất nhanh)
        url_info = await get_original_url(url)
        final_url = url_info["final_url"]
        meta_url = url_info["meta_url"]
        print(f"🔗 URL gốc: {url} - Link Meta: {meta_url} - Link cuối cùng: {final_url}")
        domain = get_domain_name(final_url)
        
        # 2. Chạy AI và check DB đồng thời
        is_reported = await PhishingReport.filter(url__icontains=domain, real=True).exists()
        
        features = await extract_features_async(meta_url)
        report = get_risk_report(meta_url, features)
        
        is_phishing = report["is_phishing"] or is_reported
        loop = asyncio.get_event_loop()
        country, org = "Unknown", "Unknown"
        country_code= features["country"]
        try:
            country = pycountry.countries.get(alpha_2=country_code).name
        except:
            country = "Unknown"
        org = features.get("org", "Unknown")   
        
        score = report["risk_score"]

        return {
            "url": url,
            "meta_url": meta_url,
            "final_url": final_url,
            "is_phishing": is_phishing,
            "country": country,
            "org": org,
            "risk_score": score,
            "color": report["color"],
            "red_flags": report["red_flags"],
            "level": report["level"],
            "status": "success"
        }
    except Exception as e:
        return {"url": url, "status": "error", "message": str(e)}

@app.post("/scan-links")
async def scan_multiple_links(data: UrlList):
    
    # Xử lý tối đa 10 link 
    process_urls = list(set(data.urls))[:10]
    results = []
    
    tasks = [process_single_url(u) for u in process_urls]
    results = await asyncio.gather(*tasks)
    
    return results


# Run API with uvicorn
if __name__ == '__main__':
    uvicorn.run(app,host="127.0.0.1",port=8000)
