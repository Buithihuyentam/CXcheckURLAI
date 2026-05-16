# Phân tích Luồng Extension CheckPost

## Tổng quan kiến trúc 3 tầng

```
[Trang web X.com]           [Background SW]          [Backend Python]
  contentScript.js   <-->   background.js    <-->   FastAPI (app.py)
  popup.js           <-->   background.js
```

Có 5 luồng độc lập đang hoạt động trong Extension.

---

## Luồng 1: Auto-Scan (Luồng chính - Quét bài đăng)

**Mô tả:** Tự động phát hiện và quét tất cả link `t.co` khi người dùng lướt X.

```
contentScript.js                background.js              Backend (app.py)
       |                               |                          |
[MutationObserver]                     |                          |
  phát hiện <a href="t.co/...">        |                          |
       |                               |                          |
[queueLink(a)]                         |                          |
  add vào pendingUrls Set              |                          |
  add class "cp-scan-loading"          |                          |
       |                               |                          |
[scheduleBatch()] -- debounce 600ms -->|                          |
       |                               |                          |
[processBatch()]                       |                          |
  gom tối đa 30 URL                    |                          |
       |                               |                          |
  sendMessage(AUTO_SCAN, urls[])  ---> |                          |
                                  [fetch POST /scan-links]  ----> |
                                       |                    [resolve_batch]
                                       |                    [predict_single_url x N]
                                       |                    [return results[]]
                                  [saveResultsToStorage]   <----- |
                                  [updateTabBadge]                 |
                                  [sendMessage UPDATE_POPUP_UI]    |
                                       |                          |
       | <-- sendResponse(results) --- |                          |
[markDomElements(item)]                |                          |
  applyHighlight() -> tô màu thẻ <a>  |                          |
  localCache.set(url, item)           |                          |
```

**Vấn đề quan trọng:** Background gọi `sendResponse` TRƯỚC khi `saveResultsToStorage` + `UPDATE_POPUP_UI` hoàn thành (do thứ tự code). Điều này an toàn nhưng có thể gây race condition nếu Popup mở ngay lúc đó.

---

## Luồng 2: Popup UI (Người dùng mở Popup)

**Mô tả:** Khi người dùng click icon Extension, Popup load và hiển thị danh sách link đã quét.

```
popup.js                     background.js            chrome.storage.local
    |                               |                          |
[DOMContentLoaded]                  |                          |
[App.init()]                        |                          |
    |                               |                          |
sendMessage(GET_SCANNED_DATA)  ---> |                          |
                               query active tab id             |
                               storage.get(tab_${id})   ----> |
                                    |               <--------- |
                               sendResponse(allData[])         |
    | <--- allData[] -------------- |                          |
[UI.refreshList(data)]              |                          |
  renderCard(item) cho mỗi link     |                          |
    |                               |                          |
[chrome.runtime.onMessage]          |                          |
  lắng nghe UPDATE_POPUP_UI         |                          |
  -> UI.refreshList(newResults)     |                          |
  (cập nhật real-time khi có scan mới)                        |
```

**Luồng ngược (Real-time push):**
Khi Background hoàn thành scan mới, nó broadcast `UPDATE_POPUP_UI` xuống Popup (nếu đang mở). Popup cập nhật danh sách ngay mà không cần người dùng đóng mở lại.

---

## Luồng 3: SPA Navigation (Chuyển trang Back/Forward)

**Mô tả:** X.com là SPA (React). Khi bấm Back/Forward hoặc click vào bài viết, URL thay đổi nhưng trang không reload.

```
contentScript.js                    background.js          chrome.storage
       |                                  |                      |
[MutationObserver trên document.head]     |                      |
  phát hiện location.href thay đổi       |                      |
       |                                  |                      |
[window.pageshow event]                   |                      |
  (bfcache restore)                       |                      |
       |                                  |                      |
[resetAndScan()]                          |                      |
  pendingUrls.clear()                     |                      |
  processedLinks = new WeakSet()  <- giải phóng RAM             |
  localCache.clear()              <- ép quét lại                |
       |                                  |                      |
  setTimeout(500ms)                       |                      |
    querySelectorAll(t.co links)          |                      |
    delete dataset.checkpostStatus        |                      |
    queueLink(a) cho từng link            |                      |
       |                                  |                      |
  --> Tiếp tục Luồng 1 (Auto-Scan)       |                      |
```

**Lý do delay 500ms:** React/NextJS của X cần thời gian render lại DOM sau khi thay đổi route.

---

## Luồng 4: Tooltip (Bôi đen văn bản - kiểm tra link thủ công)

**Mô tả:** Người dùng bôi đen một URL bất kỳ trên trang web để kiểm tra ngay lập tức.

```
contentScript.js               background.js             Backend (app.py)
       |                              |                         |
[mouseup event]                       |                         |
  handleSelection()                   |                         |
  kiểm tra text có dạng URL           |                         |
       |                              |                         |
[createFloatingBtn()] - hiện icon 🛡️  |                         |
  tự remove sau 4 giây               |                         |
       |                              |                         |
[onmousedown trên icon]               |                         |
[showTooltip()]                       |                         |
  render skeleton "Đang phân tích..."  |                         |
       |                              |                         |
sendMessage(checkSingleLink, url) --> |                         |
                              fetch GET /analyze?url=... -----> |
                                      |                  [predict_phishing]
                                      |                  [return result]
                              sendResponse(data)  <-----------  |
       | <-- response.data ---------- |                         |
  render kết quả thật vào Tooltip     |                         |
  (domain, risk_score, level, flags)  |                         |
```

**Điểm đặc biệt:** Luồng này dùng `/analyze` (GET, đơn lẻ) thay vì `/scan-links` (POST, batch). Không lưu vào storage, không cập nhật badge.

---

## Luồng 5: Report URL

**Mô tả:** Người dùng báo cáo một link là độc hại từ Popup.

```
popup.js                        background.js           Backend (app.py)
    |                                 |                       |
[Btn "🚩 Report" trong card]          |                       |
[handleInlineReport(item, btn)]       |                       |
    |                                 |                       |
sendMessage(REPORT_URL, url)  ------> |                       |
                              fetch POST /report -----------> |
                                      |               [PhishingReport.save()]
                              sendResponse(success)  <------- |
    | <-- response.success ---------- |                       |
  btn.innerText = "✅ Reported"        |                       |
```

---

## Vấn đề (Bugs) phát hiện trong quá trình phân tích

| # | File | Vấn đề | Mức độ |
|---|------|--------|--------|
| 1 | `background.js:103-104` | `GET_SCANNED_DATA` có `return true` + `break` sau IIFE lồng nhau - `break` không bao giờ chạy, gây lỗi tiềm ẩn | Thấp |
| 2 | `background.js:51,354` | `scan-links` xử lý `data.urls` không giới hạn ở background nhưng `app.py` lại cắt `[:10]`, làm mất 20 link nếu batch size = 30 | Cao |
| 3 | `contentScript.js:190` | `scheduleBatch()` dùng `if (scanTimer) return` - nếu timer đang chạy, link mới vào sẽ bị bỏ qua, không được schedule lại | Trung bình |
| 4 | `background.js:235` | `contextMenus.onClicked` gọi endpoint `/review` và `/news` - các endpoint này không tồn tại trong `app.py` hiện tại | Cao |
| 5 | `predictor_improved.py:176` | Mỗi lần extract features lại tạo mới `httpx.AsyncClient` - không dùng Connection Pool, TCP handshake lại từ đầu mỗi request | Cao |
