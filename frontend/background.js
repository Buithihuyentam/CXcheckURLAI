const server_url = "http://localhost:8000/";
let activeTabUrl = "";
let userAllowedUrls = {};
let onoffstate;
// 1. Lắng nghe tin nhắn từ Popup để lưu trạng thái
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message.action === "ALLOW_ACCESS") {
    const tabId = sender.tab.id; // Lấy ID của tab hiện tại
    userAllowedUrls[tabId] = message.url; // Lưu lại URL này là an toàn cho tab này
    sendResponse({ status: "ok" });
  }
  if (message.checkboxState) {
    chrome.storage.local.set({ checkPostState: message.checkboxState });
    console.log("Đã lưu trạng thái mới:", message.checkboxState);
  }
});

// 2. Lắng nghe sự kiện chuyển trang/load trang
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // 1. Chỉ chạy khi trang đã load xong hoàn toàn
  if (changeInfo.status !== "complete") return;

  // 2. Lấy URL (đảm bảo không null)
  const currentUrl = tab.url;
  if (!currentUrl) return;

  // 3. BỎ QUA nếu là trang nội bộ hoặc trang cảnh báo
  if (
    currentUrl.startsWith("chrome://") ||
    currentUrl.includes("override.html")
  ) {
    return;
  }

  // 4. KIỂM TRA WHITELIST (Quan trọng để thoát vòng lặp)
  // Nếu URL này đã được user cho phép ở tab này -> Dừng kiểm tra
  if (userAllowedUrls[tabId] && currentUrl === userAllowedUrls[tabId]) {
    console.log("URL nằm trong Whitelist (User đã bấm Tiếp tục). Bỏ qua.");
    return;
  }

  // 5. Lấy trạng thái ON/OFF từ Storage
  chrome.storage.local.get(["checkPostState"], function (result) {
    let onoffstate = result.checkPostState || "checked"; // Mặc định là bật

    // Nếu Extension đang tắt -> Dừng
    if (onoffstate === "unchecked") {
      console.log("Extension đang tắt via Popup.");
      return;
    }

    console.log(`Đang kiểm tra: ${currentUrl}`);

    // --- GỌI API KIỂM TRA PHISHING ---
    const phishing_api = `${server_url}phishing?url=${encodeURIComponent(
      currentUrl
    )}`;

    fetch(phishing_api)
      .then((response) => {
        if (!response.ok) throw new Error("Lỗi kết nối server");
        return response.json();
      })
      .then((data) => {
        console.log("Kết quả từ server:", data);

        // CHÚ Ý: Logic kiểm tra kết quả trả về
        // Giả sử server trả về { is_phishing: true }
        // Bạn có thể sửa logic if này tùy theo response thực tế của server bạn
        const isPhishing = data === true || data.is_phishing === true;

        // --- TEST MODE (Nếu muốn test giao diện thì bỏ comment dòng dưới) ---
        // const isPhishing = true;

        if (isPhishing) {
          console.warn("CẢNH BÁO: Phát hiện trang lừa đảo!");

          // Chuyển hướng sang trang cảnh báo
          const warningUrl =
            chrome.runtime.getURL("override.html") +
            "?url=" +
            encodeURIComponent(currentUrl);
          chrome.tabs.update(tabId, { url: warningUrl });
        } else {
          showToast("CheckPost", "Trang này an toàn.", "success");
          console.log("Trang web an toàn.");
        }
      })
      .catch((error) => {
        console.error("Không thể kiểm tra phishing:", error);
      });
  });
});

chrome.runtime.onInstalled.addListener(() => {
  // adds context menu needed for our extension on installation
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "review_check",
      title: "Review Check",
      contexts: ["selection"],
    });

    chrome.contextMenus.create({
      id: "news_check",
      title: "News Check",
      contexts: ["selection"],
    });
  });
  console.log("contenxtMenu done");
});

// background.js

function showToast(title, message, type = "success") {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.scripting.executeScript({
        target: { tabId: tabs[0].id },
        func: (t, m, type) => {
          // 1. Xóa Host cũ (Vì ta dùng Shadow DOM nên phải xóa cái vỏ bên ngoài)
          const oldHost = document.getElementById("checkpost-toast-host");
          if (oldHost) oldHost.remove();

          // 2. Tạo Host (Cái vỏ chứa Shadow DOM)
          const host = document.createElement("div");
          host.id = "checkpost-toast-host";
          // Đặt host nằm đè lên tất cả nhưng không chặn click chuột vào vùng rỗng
          Object.assign(host.style, {
            position: "fixed",
            top: "0",
            right: "0",
            zIndex: "2147483647",
            pointerEvents: "none", // Để chuột có thể bấm xuyên qua vùng trống
          });

          // 3. Tạo Shadow DOM (Căn phòng kín)
          const shadow = host.attachShadow({ mode: "open" });

          // 4. Tạo CSS (Nằm gọn trong Shadow, không cần tiền tố, không sợ xung đột)
          const style = document.createElement("style");
          style.textContent = `
            /* Animation */
            @keyframes slideFadeIn {
              from { transform: translateY(-14px) scale(0.97); opacity: 0; }
              to { transform: translateY(0) scale(1); opacity: 1; }
            }
            @keyframes slideFadeOut {
              to { transform: translateY(-10px); opacity: 0; }
            }

            /* Container chính */
            .fake-news-toast {
              /* Reset toàn bộ style */
              all: initial;
              font-family: "Segoe UI", Roboto, Arial, sans-serif;
              box-sizing: border-box;
              
              /* Vị trí */
              position: fixed;
              top: 20px;
              right: 20px;
              
              /* Giao diện */
              padding: 18px 20px;
              border-radius: 16px;
              min-width: 320px;
              max-width: 400px;
              color: #fff;
              box-shadow: 0 14px 30px rgba(0, 0, 0, 0.25), 0 6px 12px rgba(0, 0, 0, 0.18);
              
              /* Animation */
              animation: slideFadeIn 0.45s cubic-bezier(0.4, 0, 0.2, 1);
              pointer-events: auto; /* Bật lại click chuột cho thông báo */
              display: flex;
              flex-direction: column;
              gap: 4px;
            }

            /* Màu nền mặc định (Xanh) */
            .fake-news-toast.blue {
              background: linear-gradient(135deg, #00c6ff, #0072ff);
            }
            
            /* Màu nền cảnh báo (Đỏ) */
            .fake-news-toast.red {
              background: linear-gradient(135deg, #ff6a6a, #ff3b3b);
            }

            /* Text */
            strong {
              display: block;
              font-size: 16px;
              font-weight: 600;
              color: #fff;
              margin-bottom: 2px;
            }
            span {
              display: block;
              font-size: 13.5px;
              line-height: 1.4;
              color: rgba(255, 255, 255, 0.95);
            }

            /* Hiệu ứng ẩn */
            .fake-news-toast.hide {
              animation: slideFadeOut 0.35s ease forwards;
            }
          `;

          // 5. Tạo Element thông báo
          const toast = document.createElement("div");
          const colorClass = type === "error" ? "red" : "blue";
          toast.className = `fake-news-toast ${colorClass}`;
          toast.innerHTML = `
              <strong>${t}</strong>
              <span>${m}</span>
          `;

          // 6. Lắp ghép vào Shadow DOM
          shadow.appendChild(style);
          shadow.appendChild(toast);
          document.body.appendChild(host);

          // 7. Logic tự hủy
          setTimeout(() => {
            toast.classList.add("hide");
            toast.addEventListener("animationend", () => {
              host.remove(); // Xóa cả cái vỏ host
            });
            // Fallback an toàn
            setTimeout(() => {
              if (host.parentNode) host.remove();
            }, 400);
          }, 3500);
        },
        args: [title, message, type],
      });
    }
  });
}

chrome.contextMenus.onClicked.addListener((clickData, tab) => {
  if (clickData.menuItemId == "review_check" && clickData.selectionText) {
    let reviewText = clickData.selectionText;
    const review_url = `${server_url}review`;

    // Gửi thông báo "Đang xử lý" (Optional)
    // chrome.tabs.sendMessage(tab.id, { action: "processing" });

    fetch(review_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ review: reviewText }),
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("Prediction Review: " + data.prediction);

        // THAY VÌ showToast, TA GỬI MESSAGE SANG CONTENT SCRIPT
        chrome.tabs.sendMessage(tab.id, {
          action: "show_result", // Tên hành động để content nhận biết
          type: "review", // Loại: review hay news
          prediction: data.prediction, // Kết quả: REAL hay FAKE
        });
      })
      .catch((error) => console.log("Lỗi fetch review: " + error));
  }

  // --- LOGIC CHO NEWS ---
  else if (clickData.menuItemId == "news_check" && clickData.selectionText) {
    let newsText = clickData.selectionText;
    const news_url = `${server_url}news`;

    fetch(news_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ news: newsText }), // Sửa lại key cho khớp backend nếu cần
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("Prediction News: " + data.prediction);

        // GỬI MESSAGE SANG CONTENT SCRIPT
        chrome.tabs.sendMessage(tab.id, {
          action: "show_result",
          type: "news",
          prediction: data.prediction,
        });
      })
      .catch((error) => console.log("Lỗi fetch news: " + error));
  }
});
