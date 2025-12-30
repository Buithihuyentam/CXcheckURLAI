document.addEventListener("DOMContentLoaded", function () {
  // ==========================================
  // 1. KHỞI TẠO & LẤY DỮ LIỆU
  // ==========================================
  const reportBtn = document.getElementById("reportBtn");
  const reportBox = document.getElementById("reportBox");
  const proceedBtn = document.getElementById("proceedBtn");
  const backBtn = document.getElementById("backBtn");
  const urlDisplay = document.getElementById("urlDisplay"); // Nếu bạn có thẻ hiển thị URL

  // URL API báo cáo (Cần khớp với server python của bạn)
  const REPORT_API_URL = "http://127.0.0.1:8000/report_mistake";

  // Lấy URL trang web độc hại từ tham số ?url=... trên thanh địa chỉ
  const params = new URLSearchParams(window.location.search);
  let targetUrl = params.get("url");

  // Giải mã URL (VD: https%3A%2F%2Fgoogle.com -> https://google.com)
  if (targetUrl) {
    targetUrl = decodeURIComponent(targetUrl);
  } else {
    targetUrl = "https://www.google.com"; // Fallback nếu lỗi
  }

  // Hiển thị URL lên giao diện cho người dùng thấy (nếu có thẻ id="urlDisplay")
  if (urlDisplay) {
    urlDisplay.textContent = targetUrl;
  }

  // ==========================================
  // 2. XỬ LÝ SỰ KIỆN NÚT BẤM
  // ==========================================

  // --- Nút Quay lại (Back) ---
  if (backBtn) {
    backBtn.addEventListener("click", function () {
      // Cách 1: Về trang an toàn
      window.location.href = "https://google.com";

      // Cách 2: Đóng tab (thường chỉ hoạt động nếu script mở tab này)
      // window.close();
    });
  }

  // --- Nút Tiếp tục (Proceed) - QUAN TRỌNG ---
  if (proceedBtn) {
    proceedBtn.addEventListener("click", function () {
      if (!targetUrl) {
        alert("Không tìm thấy đường dẫn gốc!");
        return;
      }

      // Gửi tin nhắn về background.js
      // Action phải khớp với background.js: "ALLOW_ACCESS"
      chrome.runtime.sendMessage(
        {
          action: "ALLOW_ACCESS",
          url: targetUrl,
        },
        (response) => {
          // Kiểm tra lỗi kết nối
          if (chrome.runtime.lastError) {
            console.error("Lỗi Extension:", chrome.runtime.lastError.message);
            // Nếu lỗi kết nối, vẫn cho người dùng đi tiếp (fallback)
            window.location.href = targetUrl;
            return;
          }

          // Nhận phản hồi từ background
          if (response && response.status === "ok") {
            console.log("Background đã chấp nhận, đang chuyển trang...");
            // Chuyển hướng trình duyệt tới trang đích
            window.location.href = targetUrl;
          }
        }
      );
    });
  }

  // --- Nút Báo cáo (Report) ---
  if (reportBtn) {
    reportBtn.addEventListener("click", function () {
      const reason = reportBox ? reportBox.value : "No reason";
      handleReportSubmit(targetUrl, reason, reportBtn, reportBox);
    });
  }
});

// ==========================================
// 3. HÀM GỬI BÁO CÁO (HELPER)
// ==========================================
function handleReportSubmit(url, reason, btnElement, inputElement) {
  // Khóa nút để tránh spam
  btnElement.disabled = true;
  const originalText = btnElement.innerText;
  btnElement.innerText = "Đang gửi...";

  const reportData = {
    url: url,
    reason: reason || "Người dùng báo cáo sai sót",
  };

  fetch("http://127.0.0.1:8000/report_mistake", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reportData),
  })
    .then((response) => {
      if (!response.ok) throw new Error("Lỗi mạng hoặc server");
      return response.json();
    })
    .then((data) => {
      console.log("Report success:", data);
      alert("Đã gửi báo cáo thành công! Cảm ơn đóng góp của bạn.");
      if (inputElement) inputElement.value = ""; // Xóa text
    })
    .catch((error) => {
      console.error("Report error:", error);
      alert("Không thể gửi báo cáo. Vui lòng kiểm tra kết nối Server.");
    })
    .finally(() => {
      // Mở lại nút
      btnElement.disabled = false;
      btnElement.innerText = originalText;
    });
}
