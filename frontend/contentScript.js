/**
 * CHECKPOST - Hệ thống Radar bảo vệ thời gian thực
 * Chuyên nghiệp hóa cho Khóa luận tốt nghiệp
 */

const CheckPost = {
  // --- CẤU HÌNH ---
  CONFIG: {
    SCAN_DEBOUNCE_MS: 600,
    MAX_BATCH_SIZE: 30,
    LINK_SELECTOR: 'article[data-testid="tweet"] a[href*="t.co"]',
  },

  // --- TRẠNG THÁI ---
  state: {
    localCache: new Map(),
    pendingUrls: new Set(),
    processedLinks: new WeakSet(),
    activeScansCount: 0,
    lastUrl: location.href,
    scanTimer: null,
    currentFloatingBtn: null,
  },

  // --- KHỞI TẠO HỆ THỐNG ---
  init() {
    console.log("🛡️ CheckPost Scanner Engine starting...");
    this.injectStyles();
    this.initUI();
    this.initEvents();
    this.syncWithStorage();
    this.startObservers();
  },

  injectStyles() {
    const style = document.createElement("style");
    style.textContent = `
            @keyframes cp-breathing {
                0%, 100% { background-color: rgba(52, 152, 219, 0.05); }
                50% { background-color: rgba(52, 152, 219, 0.2); }
            }
            .cp-tooltip {
                all: initial;
                position: absolute;
                z-index: 2147483647;
                width: 280px;
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(52, 152, 219, 0.2);
                border-radius: 14px;
                padding: 16px;
                box-shadow: 0 12px 40px rgba(0,0,0,0.15);
                font-family: 'Segoe UI', Roboto, sans-serif;
                color: #2c3e50;
                transition: opacity 0.3s ease, transform 0.3s ease;
                visibility: hidden; /* Hiện sau khi tính toán vị trí */
                opacity: 0;
                transform: translateY(10px);
            }
            .cp-tooltip.visible {
                visibility: visible;
                opacity: 1;
                transform: translateY(0);
            }
            .cp-tooltip-header {
                display: flex; align-items: center; gap: 8px;
                margin-bottom: 12px; border-bottom: 1px solid #eee; padding-bottom: 8px;
            }
            .cp-status-dot {
                width: 8px; height: 8px; border-radius: 50%; background: #bdc3c7;
            }
            .cp-status-dot.scanning { background: #3498db; animation: cp-ping-ani 1s infinite; }
            .cp-status-dot.safe { background: #2ecc71; box-shadow: 0 0 8px #2ecc71; }
            .cp-status-dot.danger { background: #e74c3c; box-shadow: 0 0 8px #e74c3c; }
            
            .cp-info-row { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px; }
            .cp-info-label { color: #7f8c8d; }
            .cp-info-value { font-weight: 600; color: #34495e; }
            
            .cp-close-btn {
                margin-top: 10px; width: 100%; padding: 6px; border: none;
                border-radius: 8px; background: #f1f2f6; cursor: pointer;
                font-size: 12px; font-weight: bold; transition: background 0.2s;
            }
            .cp-close-btn:hover { background: #dfe4ea; }
            .cp-scan-loading { animation: cp-breathing 1.5s infinite; border-radius: 4px; }
            #cp-radar {
                position: fixed; bottom: 80px; right: 25px;
                width: 46px; height: 46px; border-radius: 50%;
                background: #1a2634; border: 2px solid #3498db;
                color: #3498db; display: flex; align-items: center;
                justify-content: center; font-weight: bold; z-index: 2147483647;
                box-shadow: 0 4px 15px rgba(0,0,0,0.4);
                transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                transform: scale(0); pointer-events: none;
            }
            #cp-radar.active { transform: scale(1); }
            .cp-ping {
                position: absolute; width: 100%; height: 100%;
                border-radius: 50%; border: 2px solid #3498db;
                animation: cp-ping-ani 1.5s infinite;
            }
            @keyframes cp-ping-ani { 0% { transform: scale(1); opacity: 0.8; } 100% { transform: scale(1.6); opacity: 0; } }
        `;
    document.head.appendChild(style);
  },

  initUI() {
    this.radar = document.createElement("div");
    this.radar.id = "cp-radar";
    this.radar.innerHTML = `<div class="cp-ping"></div><span id="cp-radar-count">0</span>`;
    document.body.appendChild(this.radar);
  },

  // --- LOGIC XỬ LÝ DỮ LIỆU ---
  getHost(url) {
    try {
      return new URL(url).hostname.replace(/^www\./, "");
    } catch {
      return "";
    }
  },

  isSafe(url) {
    const host = this.getHost(url);
    if (this.CONFIG.SHORTENERS.has(host)) return false;
    return (
      this.CONFIG.SAFE_DOMAINS.has(host) ||
      [...this.CONFIG.SAFE_DOMAINS].some((d) => host.endsWith("." + d))
    );
  },

  // --- ĐIỀU KHIỂN RADAR & HIGHLIGHT ---
  updateRadar(change) {
    this.state.activeScansCount = Math.max(
      0,
      this.state.activeScansCount + change,
    );
    document.getElementById("cp-radar-count").innerText =
      this.state.activeScansCount;
    this.radar.classList.toggle("active", this.state.activeScansCount > 0);
  },

  applyHighlight(el, data) {
    if (!el || this.state.processedLinks.has(el)) return;

    el.classList.remove("cp-scan-loading");
    const isPhish = data.is_phishing;
    const isWarning = data.level?.includes("WARNING");
    const isDanger =
      data.level === "EXTREMELY DANGEROUS" || data.level === "DANGEROUS";
    let bgColor = "";
    let borderColor = "";

    // 2. Dùng if...else if để gán giá trị theo điều kiện
    if (isPhish && isDanger) {
      bgColor = "rgba(255, 71, 87, 0.15)";
      borderColor = "#ff4757";
    } else if (isWarning) {
      bgColor = "rgba(255, 165, 0, 0.15)";
      borderColor = "#ffa500";
    } else {
      // Safe -> Màu Xanh
      bgColor = "rgba(46, 204, 113, 0.12)";
      borderColor = "#2ed573";
    }
    Object.assign(el.style, {
      backgroundColor: bgColor,
      borderBottom: `2px solid ${borderColor}`,
      transition: "all 0.3s ease",
    });
    console.log(
      `Link ${data.url} được đánh dấu là ${isPhish ? "Phishing" : "Safe"}`,
    );

    el.dataset.checkpostStatus = "done";
    this.state.processedLinks.add(el);
  },

  // --- QUY TRÌNH QUÉT (SCAN ENGINE) ---
  queueLink(link) {
    if (
      !(link instanceof HTMLAnchorElement) ||
      !link.href.startsWith("http") ||
      link.dataset.checkpostStatus
    )
      return;

    this.state.pendingUrls.add(link.href);
    link.classList.add("cp-scan-loading");
    link.dataset.checkpostStatus = "pending";
    this.scheduleBatch();
  },

  scheduleBatch() {
    if (this.state.scanTimer) return;
    this.state.scanTimer = setTimeout(
      () => this.processBatch(),
      this.CONFIG.SCAN_DEBOUNCE_MS,
    );
  },

  async processBatch() {
    this.state.scanTimer = null;
    if (this.state.pendingUrls.size === 0) return;

    const batch = Array.from(this.state.pendingUrls).slice(
      0,
      this.CONFIG.MAX_BATCH_SIZE,
    );
    batch.forEach((url) => this.state.pendingUrls.delete(url));

    this.updateRadar(batch.length);

    chrome.runtime.sendMessage({ action: "AUTO_SCAN", urls: batch }, (res) => {
      this.updateRadar(-batch.length);
      if (!res?.results) return;
      console.log(`Nhận kết quả cho batch ${batch.length}:`, res.results);
      res.results.forEach((item) => {
        console.log(`Processing result for URL: ${item}`);
        this.state.localCache.set(item.url, item);
        this.markDomElements(item);
      });
    });
  },

  markDomElements(item) {
    const urls = [item.url].filter(Boolean);
    console.log("Marking URLs in DOM:", urls);
    urls.forEach((u) => {
      document
        .querySelectorAll(`a[href="${CSS.escape(u)}"]`)
        .forEach((el) => this.applyHighlight(el, item));
    });
  },

  // --- LẮNG NGHE SỰ KIỆN ---
  initEvents() {
    // Nút Back/Forward
    window.addEventListener("pageshow", () => this.resetAndScan());

    // Lựa chọn văn bản (Floating Icon)
    document.addEventListener("mouseup", () => this.handleSelection());

    // Tin nhắn từ Extension
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg.action === "SCROLL_TO_LINK") {
        this.scrollToTarget(msg);
        sendResponse({ status: "ok" });
      }
      if (msg.action === "getPageLinks") {
        sendResponse({ links: Array.from(this.state.localCache.keys()) });
      }
      return true;
    });
  },

  startObservers() {
    // Observer cho bài viết mới
    new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (node.nodeType !== 1) continue;
          node
            .querySelectorAll?.(this.CONFIG.LINK_SELECTOR)
            .forEach((a) => this.queueLink(a));
          if (node.matches?.(this.CONFIG.LINK_SELECTOR)) this.queueLink(node);
        }
      }
    }).observe(document.body, { childList: true, subtree: true });

    // Observer cho URL chuyển hướng ảo (SPA)
    new MutationObserver(() => {
      if (location.href !== this.state.lastUrl) {
        this.state.lastUrl = location.href;
        this.resetAndScan();
      }
    }).observe(document.head, { childList: true, subtree: true });
  },

  resetAndScan() {
    console.log("🔄 SPA Navigation detected, re-syncing...");
    this.state.pendingUrls.clear();
    this.state.activeScansCount = 0;
    this.updateRadar(0);
    this.syncWithStorage();
    document
      .querySelectorAll(this.CONFIG.LINK_SELECTOR)
      .forEach((a) => this.queueLink(a));
  },

  syncWithStorage() {
    chrome.runtime.sendMessage({ action: "GET_SCANNED_DATA" }, (res) => {
      res?.allData?.forEach((item) => {
        this.state.localCache.set(item.url, item);
        this.markDomElements(item);
      });
    });
  },

  // --- FLOATING ICON & TOOLTIP ---
  handleSelection() {
    setTimeout(() => {
      const sel = window.getSelection().toString().trim();
      if (sel.length > 5 && this.isValidLinkFormat(sel)) {
        const rect = window
          .getSelection()
          .getRangeAt(0)
          .getBoundingClientRect();
        this.createFloatingBtn(
          rect.right + window.scrollX,
          rect.bottom + window.scrollY + 5,
          sel,
        );
      }
    }, 50);
  },

  isValidLinkFormat(t) {
    return (
      t.includes(".") &&
      (t.startsWith("http") ||
        /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}/i.test(t))
    );
  },

  createFloatingBtn(x, y, text) {
    if (this.state.currentFloatingBtn) this.state.currentFloatingBtn.remove();
    const btn = document.createElement("div");
    btn.innerText = "🛡️";
    Object.assign(btn.style, {
      position: "absolute",
      left: `${x}px`,
      top: `${y}px`,
      width: "30px",
      height: "30px",
      background: "white",
      border: "1px solid #3498db",
      borderRadius: "50%",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      cursor: "pointer",
      zIndex: "2147483647",
      boxShadow: "0 2px 8px rgba(0,0,0,0.2)",
    });
    btn.onmousedown = (e) => {
      e.preventDefault();
      this.showTooltip(x, y + 5, text);
      btn.remove();
    };
    document.body.appendChild(btn);
    this.state.currentFloatingBtn = btn;
    setTimeout(() => btn.remove(), 4000);
  },

  showTooltip(x, y, text) {
    // 1. Xóa cái cũ
    const old = document.querySelector(".cp-tooltip");
    if (old) old.remove();

    // 2. Tạo Tooltip mới với nội dung Skeleton (Đang quét)
    const tip = document.createElement("div");
    tip.className = "cp-tooltip";
    tip.innerHTML = `
        <div class="cp-tooltip-header">
            <div class="cp-status-dot scanning"></div>
            <strong style="font-size:14px; color:#3498db">Đang phân tích...</strong>
        </div>
        <div style="font-size:12px; color:#95a5a6; margin-bottom:10px;">Link: ${text.substring(0, 30)}...</div>
        <div class="cp-info-row"><div class="cp-info-label">Độ tin cậy</div><div class="cp-info-value">--%</div></div>
    `;
    document.body.appendChild(tip);

    // 3. LOGIC CHỐNG TRÀN MÀN HÌNH
    const gap = 15;
    const tipWidth = 280;
    const tipHeight = 180; // Ước lượng chiều cao tối đa

    let finalX = x;
    let finalY = y + gap;

    // Kiểm tra mép phải
    if (finalX + tipWidth > window.innerWidth + window.scrollX) {
      finalX = window.innerWidth + window.scrollX - tipWidth - gap;
    }
    // Kiểm tra mép dưới (Nếu tràn thì đẩy lên trên vùng bôi đen)
    if (finalY + tipHeight > window.innerHeight + window.scrollY) {
      finalY = y - tipHeight - gap;
    }

    tip.style.left = `${finalX}px`;
    tip.style.top = `${finalY}px`;
    tip.classList.add("visible");

    // 4. GỌI API VÀ CẬP NHẬT DỮ LIỆU THẬT
    chrome.runtime.sendMessage(
      { action: "checkSingleLink", url: text },
      (res) => {
        if (res?.success) {
          const details = res.data.details || {};
          const isPhish = res.data.is_phishing;
          const trustScore = details.risk_score || 0;

          tip.innerHTML = `
                <div class="cp-tooltip-header">
                    <div class="cp-status-dot ${isPhish ? "danger" : "safe"}"></div>
                    <strong style="font-size:14px; color:${isPhish ? "#e74c3c" : "#2ecc71"}">
                        ${details.level || "N/A"}
                    </strong>
                </div>
                <div class="cp-info-row">
                    <span class="cp-info-label">Tên miền:</span>
                    <span class="cp-info-value">${details.domain || "N/A"}</span>
                </div>
                <div class="cp-info-row">
                    <span class="cp-info-label">Quốc gia:</span>
                    <span class="cp-info-value">${details.country || "N/A"}</span>
                </div>
                <div class="cp-info-row">
                    <span class="cp-info-label">Độ tin cậy:</span>
                    <span class="cp-info-value" style="color:${isPhish ? "#e74c3c" : "#2ecc71"}">${trustScore}%</span>
                </div>
                ${isPhish ? `<div style="font-size:11px; color:#e74c3c; margin-top:5px; padding:6px; background:rgba(231,76,60,0.1); border-radius:6px">⚠️ Đây có thể là trang web giả mạo nhằm lấy cắp thông tin.</div>` : ""}
                <button class="cp-close-btn">Đóng lại</button>
            `;
          tip.querySelector(".cp-close-btn").onclick = () => tip.remove();
        } else {
          tip.innerHTML = `<div style="padding:10px; text-align:center">Server error.</div><button class="cp-close-btn">Đóng</button>`;
          tip.querySelector(".cp-close-btn").onclick = () => tip.remove();
        }
      },
    );
  },

  scrollToTarget(msg) {
    const escaped = CSS.escape(msg.url);
    const el = document.querySelector(`a[href*="${escaped}"]`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.style.outline = "3px solid #3498db";
      setTimeout(() => (el.style.outline = "none"), 2000);
    }
  },
};

// Khởi chạy
CheckPost.init();
