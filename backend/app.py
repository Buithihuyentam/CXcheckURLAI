# Libraries and frameworks
import uvicorn
import httpx
import time
from pydantic import BaseModel
from fastapi import FastAPI
import csv
from tortoise.contrib.fastapi import register_tortoise
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from typing import List
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor
import joblib
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# Local files
from predictor_improved import predict_phishing, _is_whitelisted
from helpers import get_domain_name,check_google_batch
from models import PhishingReportSchema, reviewDetectionSchema, PhishingReport, newsDetectionSchema, mistakePhishingReport
import socket
# from debug_model

# Initialize FastAPI
app = FastAPI()

# Vì thư viện whoisdomain chạy đồng bộ (blocking), ta dùng ThreadPool để không làm treo server
executor = ThreadPoolExecutor(max_workers=10)
api_key = os.getenv("SAFEBROWSING_API_KEY", "")

# model = joblib.load("MLModels/phishing_nlp.pkl" )
# extractor = ManualFeatureExtractor()

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
async def report(payload: PhishingReportSchema):
    domain = get_domain_name(payload.url)
    if not domain:
        return {'result': 'invalid url'}
        
    # Logic chuẩn Database: Query trực tiếp thay vì tải toàn bộ bảng vào RAM
    if await PhishingReport.filter(url=domain).exists():
        return {'result': 'already reported'}
        
    new_report = PhishingReport(url=domain, reason=payload.reason)
    await new_report.save()
    return {'result': 'success'}


# report mistake phishing and save to database
@app.post('/report_mistake')
async def report_mistake(payload: PhishingReportSchema):
    domain = get_domain_name(payload.url)
    if not domain:
        return {'result': 'invalid url'}
        
    # Logic chuẩn Database: Query trực tiếp
    if await mistakePhishingReport.filter(url=domain).exists():
        return {'result': 'already reported'}
        
    # Vẫn giữ real=True (Tự động duyệt) như code cũ của bạn
    # Nếu muốn có Admin duyệt, hãy đổi thành real=False
    new_report = mistakePhishingReport(url=domain, reason=payload.reason, real=True)
    await new_report.save()
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
            report_item = await PhishingReport.get(id=id)
            with open('Datasets/phishing_site_urls.csv', 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([str(report_item.url), "bad"])
        return {'result': 'success'}
    except Exception as e:
        print(f"Error updating report: {e}")
        return {'result': 'failed'}


# check single link and return both phishing prediction and domain details when bôi đen link
@app.get("/analyze")
async def analyze_link(url: str):
    domain = get_domain_name(url)
    if not domain:
        return {"error": "Invalid URL", "is_phishing": True, "details": None}
    
    # Use the new comprehensive predict_phishing function
    prediction_result = await predict_phishing(url)
    
    if prediction_result.get("status") == "error":
        return {"error": prediction_result.get("error"), "is_phishing": True, "details": None}

    score = prediction_result["phishing_probability"] * 100 # Chuyển thành %
    h_score = prediction_result["heuristic_score"]
    
    is_phishing_in_db = await PhishingReport.filter(url=domain, real=True).exists()
    is_safe_in_db = await mistakePhishingReport.filter(url=domain, real=True).exists()
    
    is_phishing = prediction_result["is_phishing"] or is_phishing_in_db
    red_flags = prediction_result.get("red_flags", [])

    if is_safe_in_db:
        is_phishing = False
        level = "An toàn"
        color = "green"
        red_flags = ["Được báo cáo là an toàn"]
        score = 0.0
        h_score = 0
    else:
        # Tính level và color tương tự cũ để Frontend dùng
        if is_phishing:
            level = "Nguy hiểm"
            color = "red"
        elif h_score >= 30 or score >= 30:
            level = "Cảnh báo"
            color = "orange"
        else:
            level = "An toàn"
            color = "green"

    print(f"Kết quả dự đoán trong analyze:")
    print(f"    - Mức độ: {level}")
    print(f"    - Xác suất ML: {score:.2f}% | Heuristic: {h_score}/100")
    print(f"    - Cảnh báo lừa đảo: {'CÓ' if is_phishing else 'KHÔNG'}")
    
    # --- 2. Lấy thông tin chi tiết từ features đã trích xuất 
    details = {
        "domain": domain,
        "level": level,
        "risk_score": score,
        "color": color,
        "red_flags": red_flags
    }

    # --- 3. Trả về kết quả tổng hợp ---
    return {
        "url": url,
        "is_phishing": bool(is_phishing), # Chuyển về kiểu boolean thật (True/False)
        "details": details
    }


from cachetools import TTLCache

# ✅ Resolution Cache: tránh resolve lại cùng 1 t.co URL (cache 1 giờ)
_url_resolution_cache: TTLCache = TTLCache(maxsize=2000, ttl=3600)

# ✅ FIX 1: Reuse 1 client cho tất cả requests (tránh TLS handshake mỗi lần)
_client: httpx.AsyncClient | None = None

async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=5.0,  # ✅ FIX 2: Giảm timeout 10s → 5s
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
        )
    return _client


async def get_original_url(short_url: str) -> dict:
    # ✅ Kiểm tra resolution cache trước — tránh HTTP call lặp lại
    cache_key = short_url.lower().strip()
    if cache_key in _url_resolution_cache:
        return _url_resolution_cache[cache_key]

    # ✅ Fast-path: Nếu URL không phải t.co, không cần HTTP call — trả ngay
    is_tco = 't.co/' in short_url
    if not is_tco:
        data = {
            "original_url": short_url,
            "meta_url": short_url,
            "final_url": short_url,
            "status": "direct",
        }
        _url_resolution_cache[cache_key] = data
        return data

    data = {
        "original_url": short_url,
        "meta_url": short_url,
        "final_url": short_url,
        "status": "error",
    }

    try:
        client = await get_client()

        # ═══════════════════════════════════════════
        # BƯỚC 1: GET t.co → lấy meta refresh URL
        # ═══════════════════════════════════════════
        response = await client.get(short_url)
        print(f"🔗 Đã GET {short_url} - Status: {response.status_code} - Final URL after redirects: {response.url}")
        # Nếu httpx đã follow redirect thành công (không phải t.co nữa)
        if str(response.url) != short_url:
            data["meta_url"] = str(response.url)
            data["final_url"] = str(response.url)
            data["status"] = "resolved"
            _url_resolution_cache[cache_key] = data
            return data
        print(f"🔗 Đang phân tích URL: {response.url} - Vẫn là t.co, sẽ kiểm tra meta refresh...")
        # Parse meta refresh từ HTML
        html_content = response.text
        meta_match = re.search(
            r'content="0;\s*URL=\'?(.*?)\'?"', html_content, re.IGNORECASE
        )

        if not meta_match:
            data["meta_url"] = str(response.url)
            data["final_url"] = str(response.url)
            data["status"] = "meta"
            data["html"] = html_content  # truyền xuống để tránh double-fetch
            _url_resolution_cache[cache_key] = data
            return data

        # ═══════════════════════════════════════════
        # BƯỚC 2: Có meta_url → LƯU LẠI NGAY
        # ═══════════════════════════════════════════
        raw_meta_url = meta_match.group(1).replace("&amp;", "&")
        data["meta_url"] = raw_meta_url  # ✅ Luôn giữ meta_url
        print(f"🔗 Tìm thấy meta URL: {raw_meta_url} - Sẽ kiểm tra tiếp để lấy final URL...")
        # ═══════════════════════════════════════════
        # BƯỚC 3: Thử resolve meta_url → final_url
        #          Nếu fail → vẫn trả meta_url
        # ═══════════════════════════════════════════

        # 3b. HEAD request để lấy final URL — httpx tự xử lý cả DNS fail + HTTP fail
        try:
            final_response = await client.head(raw_meta_url)
            data["final_url"] = str(final_response.url)
            data["status"] = "resolved"
        except Exception:
            print(f"❌ Không thể kết nối: {raw_meta_url}")
            data["final_url"] = raw_meta_url
            data["status"] = "unreachable"

        _url_resolution_cache[cache_key] = data
        return data

    except Exception as e:
        print(f"❌ Lỗi: {e}")
        # Không cache lỗi — mỗi lần thử lại
        return data


# ✅ FIX 5: Batch resolve concurrent thay vì sequential
async def resolve_batch(short_urls: list[str], max_concurrent: int = 10) -> list[dict]:
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _resolve(url: str) -> dict:
        async with semaphore:
            return await get_original_url(url)

    return await asyncio.gather(*[_resolve(u) for u in short_urls])


# Cleanup khi shutdown server
async def close_client():
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()

async def predict_single_url(url: dict) -> dict:
    t0 = time.perf_counter()
    url_final = url["final_url"]
    prefetched_html = url.get("html")  # HTML đã fetch từ bước resolve
    domain = get_domain_name(url_final)
    is_phishing_in_databse = await PhishingReport.filter(url=domain,real=True).all().exists()
    is_safe_in_db = await mistakePhishingReport.filter(url=domain,real=True).all().exists()
    
    prediction_result = await predict_phishing(url_final, prefetched_html=prefetched_html)
    
    if prediction_result.get("status") == "error":
        score = 0
        h_score = 0
        is_phish = is_phishing_in_databse
        level = "Nguy hiểm" if is_phish else "Không xác định"
        color = "red" if is_phish else "gray"
        red_flags = []
    else:
        score = prediction_result.get("phishing_probability", 0) * 100
        h_score = prediction_result.get("heuristic_score", 0)
        is_phish = prediction_result.get("is_phishing", False) or is_phishing_in_databse
        
        if is_safe_in_db:
            is_phish = False
            level = "An toàn"
            color = "green"
            red_flags = ["Được báo cáo là an toàn"]
            score = 0.0
            h_score = 0
        else:
            if is_phish:
                level = "Nguy hiểm"
                color = "red"
            elif h_score >= 30 or score >= 30:
                level = "Cảnh báo"
                color = "orange"
            else:
                level = "An toàn"
                color = "green"
            red_flags = prediction_result.get("red_flags", [])

    results = {
        "url": url["original_url"],
        "meta_url": url["meta_url"],
        "final_url": url["final_url"],
        "is_phishing": is_phish,
        "risk_score": score,
        "color": color,
        "red_flags": red_flags,
        "level": level,
    }
    elapsed = (time.perf_counter() - t0) * 1000
    print(f"⏱️  [{color.upper():6}] {url_final[:55]} — {elapsed:.0f}ms")
    return results

@app.post("/scan-links")
async def scan_multiple_links(data: UrlList):
    t_start = time.perf_counter()
    process_urls = list(dict.fromkeys(data.urls))[:30]
    results = await resolve_batch(process_urls, max_concurrent=10)
    t_resolve = time.perf_counter()
    tasks = [predict_single_url(r) for r in results]
    results = await asyncio.gather(*tasks)
    t_end = time.perf_counter()
    print(f"\n📊 BATCH SUMMARY: {len(results)} links | resolve={((t_resolve-t_start)*1000):.0f}ms | predict={((t_end-t_resolve)*1000):.0f}ms | TOTAL={(t_end-t_start)*1000:.0f}ms\n")
    return results


# Run API with uvicorn
if __name__ == '__main__':
    uvicorn.run(app,host="127.0.0.1",port=8000)
