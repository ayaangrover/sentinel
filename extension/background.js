const serverUrl = "https://sentinel.ayaangrover.hackclub.app";
let token = null;
let whitelist = [];

function getField(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (data) => resolve(data[key]));
  });
}

function setField(obj) {
  return new Promise((resolve) => {
    chrome.storage.local.set(obj, resolve);
  });
}

async function login() {
  const email = await getField("email");
  const password = await getField("password");
  if (!email || !password) return false;
  const res = await fetch(`${serverUrl}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) return false;
  const data = await res.json();
  token = data.token;
  await setField({ token });
  return true;
}

async function authFetch(path, body) {
  if (!token) token = await getField("token");
  if (!token) {
    const ok = await login();
    if (!ok) return;
  }
  const res = await fetch(`${serverUrl}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token
    },
    body: JSON.stringify(body)
  });
  if (res.status === 401) {
    token = null;
    await setField({ token: null });
    await login();
    return authFetch(path, body);
  }
  return res;
}

async function captureAndSendScreenshot() {
  chrome.tabs.captureVisibleTab(null, { format: "png" }, async (dataUrl) => {
    if (!dataUrl) return;
    const timestamp = Date.now();
    await authFetch("/capture", { dataUrl, timestamp });
  });
}

async function sendActivity(url) {
  await authFetch("/track", { tabVisited: url });
}

async function updateWhitelist() {
  if (!token) await login();
  if (!token) return;
  const res = await fetch(`${serverUrl}/rules`, {
    headers: { "Authorization": "Bearer " + token }
  });
  if (!res.ok) return;
  const rules = await res.json();
  whitelist = rules.map(r => r.condition.url);

  let dynamicRules = [];
  let ruleId = 1;
  whitelist.forEach((url) => {
    dynamicRules.push({
      id: ruleId++,
      priority: 2,
      action: { type: "allow" },
      condition: { urlFilter: url, resourceTypes: ["main_frame"] }
    });
  });
  dynamicRules.push({
    id: 9999,
    priority: 1,
    action: { type: "block" },
    condition: { regexFilter: "https?://.*", resourceTypes: ["main_frame"] }
  });

  const removeIds = dynamicRules.map((r) => r.id);
  chrome.declarativeNetRequest.updateDynamicRules(
    {
      removeRuleIds: removeIds,
      addRules: dynamicRules
    },
    () => {}
  );
}

updateWhitelist();
setInterval(updateWhitelist, 5000);

chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (message.email && message.password) {
    setField({ email: message.email, password: message.password }).then(async () => {
      await login();
      sendResponse({ status: "ok" });
    });
    return true;
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab && tab.url) sendActivity(tab.url);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url && tab.active) sendActivity(changeInfo.url);
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.tabs.create({ url: "https://ayaangrover.is-a.dev/sentinel/website/student/" });
});

chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) return;
  chrome.tabs.query({ active: true, windowId }, (tabs) => {
    if (tabs.length > 0 && tabs[0].url) sendActivity(tabs[0].url);
  });
});

setInterval(captureAndSendScreenshot, 1000);