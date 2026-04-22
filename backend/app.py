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

# Local files
from helpers import get_domain_name, reviewTester, phish_model_ls
from models import PhishingReportSchema, reviewDetectionSchema, PhishingReport, newsDetectionSchema, mistakePhishingReport
from news_predictor import PredictionModel

# Initialize FastAPI
app = FastAPI()

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

# API with prediction
@app.get('/phishing')
async def predict(url: str):
    # original_url = await get_original_url(url)
    
    # 2. Trích xuất domain
    domain = get_domain_name(url)
    
    # 3. Khởi tạo kết quả mặc định là False (An toàn)
    is_phishing = False

    # 4. Kiểm tra trong Database (Danh sách đen - Blacklist)
    # Tối ưu: Chỉ tìm đúng domain đó thay vì lấy toàn bộ list về rồi so sánh
    is_reported = await PhishingReport.filter(url__icontains=domain, real=True).exists()
    
    if is_reported:
        is_phishing = True
    else:
        # 5. Nếu DB không có, mới dùng Model AI để dự đoán
        X_predict = [str(domain)]
        y_Predict = phish_model_ls.predict(X_predict)
        
        # Model thường trả về mảng, ví dụ ['bad'] hoặc ['good']
        if y_Predict[0] == 'bad':
            is_phishing = True

    # 6. Trả về kết quả cuối cùng
    return {
        "url": url,
        "domain": domain,
        "is_phishing": is_phishing
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


# Get website details from whois


@app.get('/details')
async def whois(url: str):
    print(f"Fetching details for URL: {url}")
    original_url= await get_original_url(url)
    domain = get_domain_name(original_url["final_url"])
    try:
        whois_data = whoisdomain.query(domain)
        name = whois_data.name
        registrar = whois_data.registrar
        registrant_country = whois_data.registrant_country
        creation_date = whois_data.creation_date.strftime('%Y/%m/%d')
        expiration_date = whois_data.expiration_date.strftime('%Y/%m/%d')
        last_updated = whois_data.last_updated.strftime('%Y/%m/%d')
        dnssec = whois_data.dnssec
        registrant = whois_data.registrant
        emails = whois_data.emails
        try:
            country_name = pycountry.countries.get(alpha_2=registrant_country).name
        except:
            country_name = 'Unknown'
        
    except:
        name = 'Unknown'
        registrar = 'Unknown'
        registrant_country = 'Unknown'
        creation_date = 'Unknown'
        expiration_date = 'Unknown'
        last_updated = 'Unknown'
        dnssec = 'Unknown'
        registrant = 'Unknown'
        emails = 'Unknown'
        country_name = 'Unknown'
    print(name, registrar, registrant_country, creation_date, expiration_date, last_updated, dnssec, registrant, emails, country_name)	
    return { 
        "name": name,
        "registrar": registrar, 
        "registrant_country": registrant_country, 
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "last_updated": last_updated,
        "dnssec": dnssec,
        "registrant": registrant, 
        "emails": emails,
        "country_name": country_name,
        "domain" : domain
        }

# check single link and return both phishing prediction and domain details when bôi đen link
@app.get("/analyze")
async def analyze_link(url: str):
    print(f"Analyzing URL: {url}")
    domain = get_domain_name(url)
    if not domain:
        return {"error": "Invalid URL", "is_phishing": True, "details": None}

    X_predict = [str(domain)]
    y_Predict = phish_model_ls.predict(X_predict)
    
    is_in_db = await PhishingReport.filter(url=domain, real=True).exists()
    
    is_phishing = (y_Predict[0] == 'bad') or is_in_db

    try:
        whois_data = whoisdomain.query(domain)
        registrant_country = whois_data.registrant_country
        try:
            country_name = pycountry.countries.get(alpha_2=registrant_country).name
        except:
            country_name = 'Unknown'

        # Format lại các thông tin chi tiết
        details = {
            "domain": domain,
            "registrar": whois_data.registrar or "Unknown",
            "country": country_name,
            "country_code": registrant_country or "Unknown",
            "creation_date": whois_data.creation_date.strftime('%Y/%m/%d') if whois_data.creation_date else "Unknown",
            "org": whois_data.registrar or "Unknown" # Thường dùng Registrar làm Org nếu không có field Org riêng
        }
    except Exception as e:
        print(f"WHOIS Error: {e}")
        details = {
            "domain": domain,
            "registrar": "Unknown",
            "country": "Unknown",
            "country_code": "Unknown",
            "creation_date": "Unknown",
            "org": "Unknown"
        }

    # --- 3. Trả về kết quả tổng hợp ---
    return {
        "url": url,
        "is_phishing": bool(is_phishing), # Chuyển về kiểu boolean thật (True/False)
        "details": details
    }


@app.post("/scan-links")
async def scan_multiple_links(data: UrlList):
    urls = data.urls
    results = []
    
    # Chỉ xử lý tối đa 10 link để tránh quá tải, lọc trùng link
    process_urls = list(set(urls))[:10]

    for url in process_urls:
        print(f"Processing URL: {url}")
        try:
            # 1. Giải mã link rút gọn
            decoded_data = await get_original_url(url)
            
            meta_link = decoded_data["meta_url"]   # Để hiện lên popup
            final_link = decoded_data["final_url"] # Để check phishing/whois
            domain = get_domain_name( final_link )
            
            if not domain:
                continue

            # 2. Kiểm tra Phishing (DB trước -> AI sau)
            is_phishing = False
            is_reported = await PhishingReport.filter(url__icontains=domain, real=True).exists()
            
            if is_reported:
                is_phishing = True
            else:
                # Chỉ dự đoán bằng AI nếu DB chưa có
                X_predict = [str(domain)]
                y_Predict = phish_model_ls.predict(X_predict)
                if y_Predict[0] == 'bad':
                    is_phishing = True

            # 3. Khởi tạo thông tin cơ bản
            info = {
                "url": url,
                "real_link": meta_link,
                "original_url":  final_link,
                "domain": domain,
                "is_phishing": is_phishing,
                "country": "Unknown",
                "org": "Unknown"
            }
            
            # 4. Tra cứu WHOIS (Bọc trong try-except riêng để không làm hỏng cả vòng lặp)
            try:
                whois_data = whoisdomain.query(domain)
                if whois_data:
                    # registrant_country thường chính xác hơn cregistrant_country
                    country = getattr(whois_data, 'registrant_country', "Unknown")
                    # Nếu trả về mảng thì lấy phần tử đầu
                    if isinstance(country, list): country = country[0]
                    
                    info["country"] = country if country else "Unknown"
                    info["org"] = getattr(whois_data, 'registrar', "Unknown")
            except Exception as e:
                print(f"Lỗi WHOIS cho domain {domain}: {e}")

            results.append(info)

        except Exception as e:
            # Nếu một link bị lỗi nặng, vẫn tiếp tục với link tiếp theo
            print(f"Lỗi xử lý link {url}: {e}")
            results.append({
                "url": url,
                "is_phishing": False,
                "error": "Could not process"
            })
        
    return results

# Run API with uvicorn
if __name__ == '__main__':
    uvicorn.run(app,host="127.0.0.1",port=8000)
