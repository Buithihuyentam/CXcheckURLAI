const server_url = "http://localhost:8000/";
let details_url = "";
let activeTabUrl = "";

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  let activeTab = tabs[0];
  activeTabUrl = activeTab.url;
  details_url = `${server_url}details?url=${encodeURIComponent(activeTabUrl)}`;

  document.getElementById("siteUrl").innerText = "Loading...";

  fetch(details_url)
    .then((response) => {
      if (!response.ok) throw new Error("Network response was not ok");
      return response.json();
    })
    .then((data) => {
      // Hàm phụ để xử lý hiển thị: nếu Unknown thì hiện thông báo thân thiện hơn
      const displayValue = (val, fallback = "Không xác định") =>
        val === "Unknown" || !val ? fallback : val;

      // 1. Hiển thị ngày đăng ký (Rất quan trọng để check uy tín)
      document.getElementById(
        "detail-1"
      ).innerText = `Registered: ${displayValue(data.creation_date)}`;

      // 2. DNSSEC (Thông tin kỹ thuật, có thể giữ hoặc thay bằng Ngày hết hạn)
      document.getElementById(
        "detail-2"
      ).innerText = `Expires  : ${displayValue(data.expiration_date)}`;

      // 3. Quốc gia
      document.getElementById("detail-3").innerText = `Country:\n${displayValue(
        data.country_name
      )}`;

      // 4. Tổ chức sở hữu
      document.getElementById(
        "detail-4"
      ).innerText = `Organization:\n ${displayValue(
        data.registrant,
        "Ẩn thông tin"
      )}`;

      // 5. Tên miền chính (Tiêu đề)
      document.getElementById("siteUrl").innerText = data.domain.toUpperCase();
    })
    .catch((error) => {
      document.getElementById("siteUrl").innerText = "Lỗi tải dữ liệu";
      // Xóa trắng các dòng detail nếu lỗi
      ["detail-1", "detail-2", "detail-3", "detail-4"].forEach((id) => {
        document.getElementById(id).innerText = "";
      });
    });
});

const report_url = `${server_url}report`;

document.getElementById("submitReport").addEventListener("click", function () {
  let reportData = {
    url: activeTabUrl,
    reason: document.getElementById("reason").value,
  };

  fetch(report_url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(reportData),
  })
    .then((response) => response.json())
    .then((data) => {
      document.getElementById("reason").value = "";
      document.getElementById("submitReport").innerText = `${data.result}`;
      let submitButton = document.getElementById("submitReport");
      submitButton.disabled = true;
    })
    .catch((error) => console.log(error));
});
// 1. Lấy thẻ checkbox
let checkbox = document.getElementById("toggleCheckBox");

// 2. Khi mở Popup: Đọc trạng thái từ chrome.storage để hiển thị đúng
// Lưu ý: Key phải trùng với bên background.js là "checkPostState"
chrome.storage.local.get(["checkPostState"], function (result) {
  // Nếu chưa có dữ liệu (lần đầu cài), mặc định là "checked"
  let state = result.checkPostState || "checked";

  // Cập nhật giao diện checkbox
  checkbox.checked = state === "checked";
});

// 3. Khi người dùng bấm thay đổi Checkbox
checkbox.addEventListener("change", function () {
  // Xác định trạng thái mới dựa trên việc có được tick hay không
  let newState = checkbox.checked ? "checked" : "unchecked";

  // A. Lưu ngay vào bộ nhớ chrome.storage (Để background đọc được lần sau)
  chrome.storage.local.set({ checkPostState: newState }, function () {
    console.log("Popup đã lưu trạng thái:", newState);
  });

  // B. Gửi tin nhắn cho background (Nếu background cần cập nhật biến ngay lập tức)
  // Code background cũ của bạn có đoạn lắng nghe message này, nên ta cứ giữ lại
  chrome.runtime.sendMessage({ checkboxState: newState });
});
