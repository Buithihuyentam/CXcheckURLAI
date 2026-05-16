// --- CẤU HÌNH & TRẠNG THÁI ---
const CONFIG = {
  SERVER_URL: "http://localhost:8000/",
  MAX_DISPLAY_LENGTH: 25,
};

let list = null;

let state = {
  activeTabUrl: "",
  allData: [],
  isEnabled: true,
};

// --- KHỞI TẠO ---
document.addEventListener("DOMContentLoaded", () => {
  list = document.getElementById("linkList");
  App.init();
});

const App = {
  // --- KHỞI TẠO (GIỮ) ---
  async init() {
    console.log("🚀 Initializing Popup...");
    // Thứ tự chạy: Gán sự kiện -> Lấy thông tin tab -> Lấy cài đặt -> Lấy dữ liệu cũ
    this.bindGlobalEvents();
    await this.loadCurrentTabInfo();
    this.loadSettings();
    this.requestInitialData(); // Chỉ dùng hàm này, bỏ hàm requestDataFromStorage
  },

  // --- 1. LẤY THÔNG TIN TAB HIỆN TẠI (GIỮ) ---
  async loadCurrentTabInfo() {
    // Lấy tab đang active trong cửa sổ đang được focus
    const [tab] = await chrome.tabs.query({
      active: true,
      lastFocusedWindow: true,
    });
    if (!tab) return;

    state.currentTabId = tab.id; // Lưu lại tabId vào state
    state.activeTabUrl = tab.url;

    // Cập nhật giao diện hostname
    try {
      const parsed = new URL(tab.url);
      document.getElementById("siteUrl").innerText = parsed.hostname;
    } catch (e) {}
  },

  requestInitialData() {
    // Luôn gửi kèm tabId (nếu có) để background biết chắc chắn lấy ở đâu
    chrome.runtime.sendMessage({ action: "GET_SCANNED_DATA" }, (response) => {
      if (response?.allData) {
        console.log(`📥 Nhận ${response.allData} link đã quét từ Background`);
        state.allData = response.allData;
        console.log(`📥 1 Nhận ${state.allData} link đã quét từ Background`);
        UI.refreshList();
      }
    });
  },

  // --- 3. KHÔI PHỤC CÀI ĐẶT (GIỮ) ---
  loadSettings() {
    chrome.storage.local.get(["checkPostState"], (result) => {
      const status = result.checkPostState || "checked";
      const checkbox = document.getElementById("toggleCheckBox");
      if (checkbox) checkbox.checked = status === "checked";
      UI.updateStatusHeader(status);
    });
  },

  // --- 4. GÁN SỰ KIỆN (GIỮ) ---
  bindGlobalEvents() {
    // Lắng nghe tin nhắn cập nhật "Phát thanh" từ Background
    chrome.runtime.onMessage.addListener((message) => {
      switch (message.action) {
        case "CLEAR_POPUP_UI":
          state.allData = [];
          UI.clearList();
          break;
        case "UPDATE_POPUP_UI":
          this.handleNewResults(message.newResults);
          break;
      }
    });

    // Sự kiện Nút Report
    document
      .getElementById("submitReport")
      ?.addEventListener("click", () => this.handleReport());

    // Sự kiện Checkbox ON/OFF
    document
      .getElementById("toggleCheckBox")
      ?.addEventListener("change", (e) => {
        const newState = e.target.checked ? "checked" : "unchecked";
        UI.updateStatusHeader(newState);
        chrome.storage.local.set({ checkPostState: newState });
        chrome.runtime.sendMessage({ checkboxState: newState });
      });
  },

  // --- 5. XỬ LÝ KHI CÓ LINK MỚI TRẢ VỀ (GIỮ) ---
  handleNewResults(newResults) {
    newResults.forEach((item) => {
      // Chống trùng lặp: Chỉ thêm nếu link chưa có trong mảng allData
      if (!state.allData.find((old) => old.url === item.url)) {
        state.allData.push(item);
      }
    });
    UI.refreshList();
  },

  async scrollToPost(linkItem) {
    if (!state.currentTabId) return;
    const url = linkItem.url || linkItem.final_url || linkItem.display_url;
    if (!url) return;

    chrome.tabs.sendMessage(
      state.currentTabId,
      {
        action: "SCROLL_TO_LINK",
        url,
        originalUrl: linkItem.url,
        finalUrl: linkItem.final_url,
      },
      (response) => {
        if (chrome.runtime.lastError) {
          console.warn(
            "Popup message failed:",
            chrome.runtime.lastError.message,
          );
        }
      },
    );
  },

  // --- 6. GỬI BÁO CÁO (GIỮ) ---
  async handleReport() {
    const reasonElem = document.getElementById("reason");
    const btn = document.getElementById("submitReport");
    if (!reasonElem || !reasonElem.value) return;

    try {
      const response = await chrome.runtime.sendMessage({
        action: "REPORT_URL",
        url: state.activeTabUrl,
        reason: reasonElem.value,
      });
      reasonElem.value = "";
      btn.innerText = data.result || "Sent";
      btn.disabled = true;
    } catch (err) {
      console.error("Report failed", err);
    }
  },
  // --- 7. GỬI BÁO CÁO CHO TỪNG LINK CỤ THỂ (INLINE) ---
  async handleInlineReport(item, btn) {
    const reportUrl = item.final_url ;
    if (!reportUrl) return;

    const action = btn.getAttribute("data-action") || "REPORT_URL";
    const originalColor = btn.getAttribute("data-color") || "#e74c3c";
    const originalText = btn.innerText;
    
    btn.innerText = "Đang gửi...";
    btn.disabled = true;

    try {
      const response = await chrome.runtime.sendMessage({
        action: action,
        url: reportUrl,
        reason: action === "REPORT_MISTAKE" ? "Report safe site" : "Report phishing site",
      });

      if (!response || !response.success) {
        throw new Error(response?.error || "Unknown error");
      }
      btn.innerText = "✅ Reported";
      btn.style.borderColor = "#2ecc71";
      btn.style.color = "#2ecc71";
      btn.style.background = "transparent";
      btn.onmouseover = null;
      btn.onmouseout = null;
    } catch (err) {
      console.error("Inline report failed", err);
      btn.innerText = "❌ Failed";
      btn.disabled = false;
      setTimeout(() => {
        btn.innerText = originalText;
        btn.style.borderColor = originalColor;
        btn.style.color = originalColor;
      }, 2000);
    }
  },
};

// --- GIAO DIỆN (UI) ---
const UI = {
  refreshList() {
    const loader = document.getElementById("loading");

    if (state.allData.length > 0) {
      if (loader) loader.style.display = "none";
      list.innerHTML = ""; // Xóa sạch để vẽ lại
      state.allData.forEach((item) => this.renderCard(item));
    }
  },

  clearList() {
    const loader = document.getElementById("loading");
    if (list) list.innerHTML = "";
    if (loader) {
      loader.style.display = "block";
      loader.innerText = "No links detected yet.";
    }
  },

  renderCard(item) {
    // Mapping đồng bộ với giá trị backend trả về: "green", "orange", "red", "gray"
    const colorMap = {
      green:  { hex: "#2ecc71", icon: "✅", label: "AN TOÀN" },
      orange: { hex: "#e67e22", icon: "⚠️", label: "CẢNH BÁO" },
      red:    { hex: "#e74c3c", icon: "🚫", label: "NGUY HIỂM" },
      gray:   { hex: "#95a5a6", icon: "❓", label: "KHÔNG XÁC ĐỊNH" },
    };
    const statusConfig = colorMap[item.color] || colorMap["gray"];
    const baseColor = statusConfig.hex;
    const isDarkText = item.color === "Yellow"; // Chữ đen trên nền vàng cho dễ đọc
    const displayUrl = item.meta_url || "Unknown URL";
    const shortUrl =
      displayUrl.length > 50 ? displayUrl.substring(0, 50) + "..." : displayUrl;

    const isDangerous = item.color === "red" || item.color === "orange";
    const reportBtnText = isDangerous ? "✅ Report as Safe" : "🚩 Report as Phishing";
    const reportBtnColor = isDangerous ? "#2ecc71" : "#e74c3c";
    const reportAction = isDangerous ? "REPORT_MISTAKE" : "REPORT_URL";

    const li = document.createElement("li");
    // Thêm border-left màu để nhận diện nhanh
    li.className = "card-item fade-in is-status-border";
    li.style.borderLeftColor = baseColor;

    li.innerHTML = `
      <div class="card-header" style="background-color: ${baseColor};">
        <div class="status-icon" style="margin-right: 10px;">${statusConfig.icon}</div>
        <div class="url-info">
          <div class="main-url" style="color: ${isDarkText ? "#333" : "#fff"}">${shortUrl}</div>
        </div>
        <div class="arrow" style="margin-left: auto; color: ${isDarkText ? "#333" : "#fff"}">⛛</div>
      </div>

      <div class="card-body">
        <div class="detail-row">
            <span>🔍 Risk Level:</span> 
            <b style="color: ${baseColor}; text-transform: uppercase;">${item.level || "Unknown"}</b>
        </div>
        <div class="detail-row">
            <span>📊 Safety Score:</span> 
            <b>${item.risk_score || "N/A"}%</b>
        </div>

        
        <!-- Phần giải thích cơ sở xác định -->
        <div class="red-flags-box" style="background-color: ${baseColor}15; border-color: ${baseColor}50;">
            <div style="font-weight: bold; color: ${baseColor}; font-size: 13px;">
                ${item.red_flags && item.red_flags.length > 0 ? "🚩 DẤU HIỆU NGHI VẤN:" : "✅ HỆ THỐNG XÁC NHẬN:"}
            </div>
            ${
              item.red_flags && item.red_flags.length > 0
                ? `<ul class="red-flag-list" style="color: #333;">
                    ${item.red_flags.map((flag) => `<li>${flag}</li>`).join("")}
                   </ul>`
                : `<div style="color: #27ae60; font-size: 13px; margin-top: 5px;">Mô hình không phát hiện dấu hiệu lừa đảo cấu trúc.</div>`
            }
        </div>
        
        <div class="detail-link" style="margin-top: 15px; display: flex; justify-content: flex-end; gap: 10px; align-items: center;">
          <button type="button" class="btn-inline-report" data-action="${reportAction}" data-color="${reportBtnColor}" style="
              background: transparent;
              border: 1px solid ${reportBtnColor};
              color: ${reportBtnColor};
              padding: 5px 12px;
              border-radius: 4px;
              font-size: 12px;
              font-weight: bold;
              cursor: pointer;
              transition: all 0.2s;
            " 
            onmouseover="this.style.background='${reportBtnColor}';this.style.color='#fff';"
            onmouseout="this.style.background='transparent';this.style.color='${reportBtnColor}';"
          >${reportBtnText}</button>
          <button type="button" class="btn btn-sm view-post-btn" style="background-color: ${baseColor}; color: ${isDarkText ? "#333" : "#fff"}; border: none; padding: 5px 15px; border-radius: 4px; font-weight: bold;">
            View post
          </button>
        </div>
      </div>
    `;

    const viewButton = li.querySelector(".view-post-btn");
    if (viewButton) {
      viewButton.addEventListener("click", (event) => {
        event.stopPropagation();
        App.scrollToPost(item);
      });
    }

    const reportButton = li.querySelector(".btn-inline-report");
    if (reportButton) {
      reportButton.addEventListener("click", (event) => {
        event.stopPropagation();
        App.handleInlineReport(item, reportButton);
      });
    }

    li.addEventListener("click", () => li.classList.toggle("open"));
    list.appendChild(li);
  },

  updateStatusHeader(status) {
    const header = document.getElementById("statusHeader");
    if (header) {
      header.innerText =
        status === "checked" ? "Protection Enabled" : "Protection Disabled";
      header.style.color = status === "checked" ? "#2ecc71" : "#95a5a6";
    }
  },
};
