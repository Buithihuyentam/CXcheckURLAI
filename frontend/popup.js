// --- CẤU HÌNH & TRẠNG THÁI ---
const CONFIG = {
  SERVER_URL: "http://localhost:8000/",
  MAX_DISPLAY_LENGTH: 25,
};

let state = {
  activeTabUrl: "",
  allData: [],
  isEnabled: true,
};

// --- KHỞI TẠO ---
document.addEventListener("DOMContentLoaded", () => {
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
        state.allData = response.allData;
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
      const res = await fetch(`${CONFIG.SERVER_URL}report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: state.activeTabUrl,
          reason: reasonElem.value,
        }),
      });
      const data = await res.json();
      reasonElem.value = "";
      btn.innerText = data.result || "Sent";
      btn.disabled = true;
    } catch (err) {
      console.error("Report failed", err);
    }
  },
};
// --- GIAO DIỆN (UI) ---
const UI = {
  refreshList() {
    const loader = document.getElementById("loading");
    const list = document.getElementById("linkList");

    if (state.allData.length > 0) {
      if (loader) loader.style.display = "none";
      list.innerHTML = ""; // Xóa sạch để vẽ lại
      state.allData.forEach((item) => this.renderCard(item));
    }
  },

  clearList() {
    const list = document.getElementById("linkList");
    const loader = document.getElementById("loading");
    if (list) list.innerHTML = "";
    if (loader) {
      loader.style.display = "block";
      loader.innerText = "No links detected yet.";
    }
  },

  renderCard(item) {
    const list = document.getElementById("linkList");

    // 1. Mapping màu sắc & Icon đồng bộ
    const colorMap = {
      Green: { hex: "#2ecc71", icon: "✅" },
      "Light Green": { hex: "#a2d149", icon: "✅" },
      Yellow: { hex: "#f1c40f", icon: "⚠️" },
      Orange: { hex: "#e67e22", icon: "🚫" },
      Red: { hex: "#e74c3c", icon: "🚫" },
    };

    const statusConfig = colorMap[item.color];
    const baseColor = statusConfig.hex;
    const isDarkText = item.color === "Yellow"; // Chữ đen trên nền vàng cho dễ đọc

    const displayUrl = item.meta_url || "Unknown URL";
    const shortUrl =
      displayUrl.length > 50 ? displayUrl.substring(0, 50) + "..." : displayUrl;

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
            <b>${item.score || "N/A"}%</b>
        </div>
        <div class="detail-row">
            <span>📍 Country:</span> 
            <b>${item.country || "N/A"}</b>
        </div>
        <div class="detail-row">
            <span>🏢 Provider:</span> 
            <b>${item.org || "N/A"}</b>
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
        
        <div class="detail-link" style="margin-top: 15px; display: flex; justify-content: flex-end;">
          <a href="${item.url}" target="_blank" style="color: ${baseColor}; text-decoration: none; font-weight: bold; margin-top: 5px;">Visit Link ↗</a>
          <button type="button" class="btn btn-sm view-post-btn" style="background-color: ${baseColor}; color: ${isDarkText ? "#333" : "#fff"}; margin-left: 15px; border: none; padding: 5px 15px; border-radius: 4px; font-weight: bold;">
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
