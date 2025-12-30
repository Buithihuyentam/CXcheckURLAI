// content.js

// 1. Lắng nghe tin nhắn từ Background
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  // Debug chơi chơi thì để, không thì xóa dòng alert này đi cho đỡ phiền
  // if (message.prediction !== undefined) {
  //   alert("Prediction: " + message.prediction);
  // }

  // Nếu nhận được lệnh hiển thị kết quả
  if (message.action === "show_result") {
    // -- XỬ LÝ CHO REVIEW --
    if (message.type === "review") {
      if (message.prediction === "True") {
        showToast(
          "CheckPost",
          "Review này có vẻ uy tín (Authentic)",
          "success"
        );
      } else {
        showToast(
          "CheckPost",
          "Cảnh báo: Review này có thể là Giả Fake",
          "error"
        );
      }
    }

    // -- XỬ LÝ CHO NEWS --
    else if (message.type === "news") {
      if (message.prediction === "REAL") {
        showToast("CheckPost", "Tin tức này uy tín (Authentic)", "success");
      } else {
        showToast("CheckPost", "Cảnh báo: Tin giả (Fake News)!", "error");
      }
    }
  }
});

// 2. Định nghĩa hàm showToast (TRỰC TIẾP, KHÔNG QUA TRUNG GIAN)
function showToast(title, message, type = "success") {
  // --- Bắt đầu logic vẽ giao diện trực tiếp ---

  // 1. Xóa Host cũ (nếu có)
  const oldHost = document.getElementById("checkpost-toast-host");
  if (oldHost) oldHost.remove();

  // 2. Tạo Host (Cái vỏ chứa Shadow DOM)
  const host = document.createElement("div");
  host.id = "checkpost-toast-host";

  // Style cho host
  Object.assign(host.style, {
    position: "fixed",
    top: "0",
    right: "0",
    zIndex: "2147483647", // Max z-index
    pointerEvents: "none", // Để chuột bấm xuyên qua vùng trống
  });

  // 3. Tạo Shadow DOM (Cách ly style tuyệt đối)
  const shadow = host.attachShadow({ mode: "open" });

  // 4. Tạo CSS (Nằm gọn trong Shadow)
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
      all: initial;
      font-family: "Segoe UI", Roboto, Arial, sans-serif;
      box-sizing: border-box;
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 18px 20px;
      border-radius: 16px;
      min-width: 320px;
      max-width: 400px;
      color: #fff;
      box-shadow: 0 14px 30px rgba(0, 0, 0, 0.25), 0 6px 12px rgba(0, 0, 0, 0.18);
      animation: slideFadeIn 0.45s cubic-bezier(0.4, 0, 0.2, 1);
      pointer-events: auto;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    /* Màu nền */
    .fake-news-toast.blue {
      background: linear-gradient(135deg, #00c6ff, #0072ff);
    }
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
      <strong>${title}</strong>
      <span>${message}</span>
  `;

  // 6. Lắp ghép
  shadow.appendChild(style);
  shadow.appendChild(toast);
  document.body.appendChild(host); // Gắn trực tiếp vào body trang web

  // 7. Logic tự hủy
  setTimeout(() => {
    toast.classList.add("hide");
    toast.addEventListener("animationend", () => {
      if (host) host.remove();
    });
    // Fallback an toàn
    setTimeout(() => {
      if (host && host.parentNode) host.remove();
    }, 400);
  }, 3500);
}
