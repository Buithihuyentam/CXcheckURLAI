const CONFIG = {
  SERVER_URL: "http://localhost:8000/",
  BADGE_COLOR: "#3498db",
};

// --- HELPER FUNCTIONS ---

/**
 * Cập nhật số lượng link lên icon của riêng từng Tab
 */
async function updateTabBadge(tabId) {
  const key = `tab_${tabId}`;
  const data = await chrome.storage.local.get([key]);
  const count = data[key] ? Object.keys(data[key]).length : 0;

  chrome.action.setBadgeText({
    text: count > 0 ? count.toString() : "",
    tabId,
  });
  chrome.action.setBadgeBackgroundColor({ color: CONFIG.BADGE_COLOR, tabId });
}

/**
 * Lưu dữ liệu vào Storage và cập nhật Badge
 */
async function saveResultsToStorage(tabId, newResults) {
  const key = `tab_${tabId}`;
  const data = await chrome.storage.local.get([key]);
  let currentResults = data[key] || {};

  newResults.forEach((item) => {
    const storageKey = item.original_url || item.url;
    currentResults[storageKey] = item;
  });

  await chrome.storage.local.set({ [key]: currentResults });
  await updateTabBadge(tabId);
}

// --- MESSAGE LISTENER ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;

  // Sử dụng IIFE để xử lý async bên trong listener
  (async () => {
    try {
      switch (message.action) {
        case "AUTO_SCAN":
          if (!tabId) return;
          const res = await fetch(`${CONFIG.SERVER_URL}scan-links`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls: message.urls }),
          });
          const results = await res.json();

          await saveResultsToStorage(tabId, results);

          // Trả kết quả về cho Content Script
          sendResponse({ results });

          // Phát sóng cho Popup cập nhật UI ngay lập tức
          chrome.runtime
            .sendMessage({ action: "UPDATE_POPUP_UI", newResults: results })
            .catch(() => {});
          break;

        case "RESTORE_CACHE":
          if (!sender.tab?.id) return;
          await saveResultsToStorage(sender.tab.id, message.results);
          chrome.runtime
            .sendMessage({ action: "UPDATE_POPUP_UI", newResults: message.results })
            .catch(() => {});
          break;
        case "UPDATE_BADGE":
          if (sender.tab?.id) {
            chrome.action.setBadgeText({
              text: message.count > 0 ? message.count.toString() : "",
              tabId: sender.tab.id,
            });
            chrome.action.setBadgeBackgroundColor({
              color: "#3498db",
              tabId: sender.tab.id,
            });
          }
          sendResponse({ success: true });
          break;

        case "GET_SCANNED_DATA":
          // Nếu tin nhắn gửi từ một tab, dùng tabId đó.
          // Nếu gửi từ Popup, ta mới cần query tab active.
          (async () => {
            let targetTabId;
            if (sender.tab) {
              targetTabId = sender.tab.id;
            } else {
              const [activeTab] = await chrome.tabs.query({
                active: true,
                lastFocusedWindow: true,
              });
              targetTabId = activeTab?.id;
            }

            if (targetTabId) {
              const key = `tab_${targetTabId}`;
              const data = await chrome.storage.local.get([key]);
              const allLinks = Object.values(data[key] || {});
              console.log(
                `📤 Gửi ${allLinks.length} link cho Tab ${targetTabId}`,
              );
              sendResponse({ allData: allLinks });
            } else {
              sendResponse({ allData: [] });
            }
          })();
          return true;
          break;

        case "checkSingleLink":
          const singleRes = await fetch(
            `${CONFIG.SERVER_URL}analyze?url=${encodeURIComponent(message.url)}`,
          );
          const singleData = await singleRes.json();
          sendResponse({ success: true, data: singleData });
          break;

        case "REPORT_URL":
          const reportRes = await fetch(`${CONFIG.SERVER_URL}report`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              url: message.url,
              reason: message.reason || "User reported from extension",
            }),
          });
          const reportData = await reportRes.json();
          sendResponse({ success: true, data: reportData });
          break;

        case "REPORT_MISTAKE":
          const mistakeRes = await fetch(`${CONFIG.SERVER_URL}report_mistake`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              url: message.url,
              reason: message.reason || "User reported mistake from extension",
            }),
          });
          const mistakeData = await mistakeRes.json();
          sendResponse({ success: true, data: mistakeData });
          break;

        case "ALLOW_ACCESS":
          const allowKey = `allowed_${tabId}`;
          await chrome.storage.local.set({ [allowKey]: message.url });
          sendResponse({ status: "ok" });
          break;

        default:
          // Xử lý các thay đổi checkbox state (không cần response)
          if (message.checkboxState) {
            await chrome.storage.local.set({
              checkPostState: message.checkboxState,
            });
          }
          break;
      }
    } catch (err) {
      console.error("Error in Background Message Listener:", err);
      sendResponse({ error: err.message });
    }
  })();

  return true; // Giữ cổng kết nối cho async response
});

// --- TABS EVENTS ---

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove([`tab_${tabId}`, `allowed_${tabId}`]);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // 1. Reset dữ liệu khi URL thay đổi (tránh dữ liệu trang cũ hiện ở trang mới)
  if (changeInfo.url) {
    await chrome.storage.local.remove(`tab_${tabId}`);
    chrome.action.setBadgeText({ text: "", tabId });
    chrome.runtime.sendMessage({ action: "CLEAR_POPUP_UI" }).catch(() => {});
  }

  // Chốt chặn Phishing trang chính khi load xong
  // if (changeInfo.status === "complete") {
  //   const currentUrl = tab.url;
  //   if (
  //     !currentUrl ||
  //     !currentUrl.startsWith("http") ||
  //     currentUrl.includes("override.html")
  //   )
  //     return;
  //
  //   // Kiểm tra Whitelist
  //   const allowKey = `allowed_${tabId}`;
  //   const allowed = await chrome.storage.local.get([allowKey]);
  //   if (allowed[allowKey] === currentUrl) return;
  //
  //   const settings = await chrome.storage.local.get(["checkPostState"]);
  //   if (settings.checkPostState === "unchecked") return;
  //
  //   try {
  //     const res = await fetch(
  //       `${CONFIG.SERVER_URL}analyze?url=${encodeURIComponent(currentUrl)}`,
  //     );
  //     const data = await res.json();
  //
  //     if (data.is_phishing) {
  //       const warningUrl =
  //         chrome.runtime.getURL("override.html") +
  //         "?url=" +
  //         encodeURIComponent(currentUrl);
  //       chrome.tabs.update(tabId, { url: warningUrl });
  //     }
  //   } catch (e) {
  //     console.error("Real-time Protection Error:", e);
  //   }
  // }
});

// --- CONTEXT MENUS ---

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "review_check",
    title: "URL Check",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const type = info.menuItemId === "review_check" ? "review" : "news";

  try {
    const res = await fetch(`${CONFIG.SERVER_URL}${type}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [type]: info.selectionText }),
    });
    const data = await res.json();

    chrome.tabs
      .sendMessage(tab.id, {
        action: "show_result",
        type: type,
        prediction: data.prediction,
      })
      .catch(() => {});
  } catch (err) {
    console.error("Context Menu Error:", err);
  }
});
