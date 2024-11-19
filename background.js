const VIRUSTOTAL_API_KEY = '';
const SCAN_CACHE = new Map();
const RESOURCE_CACHE = new Map();
const CACHE_DURATION = 3600000; // 1 hour in milliseconds
const RATE_LIMIT_DELAY = 15000; // 15 seconds between API calls
let lastAPICall = 0;

// Resource types to scan
const RESOURCE_TYPES = [
  'script',
  'stylesheet',
  'image',
  'object',
  'xmlhttprequest',
  'sub_frame'
];

// Initialize webRequest listener
chrome.webRequest.onCompleted.addListener(
  handleResourceLoad,
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

function handleResourceLoad(details) {
  if (RESOURCE_TYPES.includes(details.type)) {
    const resource = {
      url: details.url,
      type: details.type,
      timestamp: Date.now()
    };
    
    queueResourceScan(resource);
  }
}

async function queueResourceScan(resource) {
  // Check cache first
  if (RESOURCE_CACHE.has(resource.url)) {
    const cachedResult = RESOURCE_CACHE.get(resource.url);
    if (Date.now() - cachedResult.timestamp < CACHE_DURATION) {
      return;
    }
  }

  // Respect rate limiting
  const now = Date.now();
  if (now - lastAPICall < RATE_LIMIT_DELAY) {
    setTimeout(() => queueResourceScan(resource), RATE_LIMIT_DELAY);
    return;
  }

  await scanResource(resource);
}

async function scanResource(resource) {
  try {
    lastAPICall = Date.now();

    // First, submit URL for scanning
    const submitResponse = await fetch('https://www.virustotal.com/vtapi/v2/url/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `apikey=${VIRUSTOTAL_API_KEY}&url=${encodeURIComponent(resource.url)}`
    });

    const submitData = await submitResponse.json();

    // Wait a bit for the scan to complete
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Get the report
    const reportResponse = await fetch(
      `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(resource.url)}`
    );

    const reportData = await reportResponse.json();
    
    // Cache the result
    RESOURCE_CACHE.set(resource.url, {
      data: reportData,
      timestamp: Date.now(),
      type: resource.type
    });

    // Update storage with latest results
    updateStorageWithResource(resource.url, reportData);

    // Check if resource is malicious
    if (reportData.positives > 0) {
      notifyMaliciousResource(resource, reportData);
    }
  } catch (error) {
    console.error('Error scanning resource:', error);
  }
}

function updateStorageWithResource(url, data) {
  chrome.storage.local.get('resourceScans', (result) => {
    const resourceScans = result.resourceScans || {};
    resourceScans[url] = {
      data: data,
      timestamp: Date.now()
    };
    chrome.storage.local.set({ resourceScans });
  });
}

function notifyMaliciousResource(resource, scanData) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icon.png',
    title: 'Malicious Resource Detected',
    message: `Warning: Malicious resource detected!\nType: ${resource.type}\nURL: ${resource.url}\nDetections: ${scanData.positives}/${scanData.total}`
  });
}

// Original URL scanning code
function scanActiveTab() {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs[0]) {
      const url = tabs[0].url;
      checkURL(url);
    }
  });
}

async function checkURL(url) {
  // Check cache first
  if (SCAN_CACHE.has(url)) {
    const cachedResult = SCAN_CACHE.get(url);
    if (Date.now() - cachedResult.timestamp < CACHE_DURATION) {
      updateBadge(cachedResult.data);
      return;
    }
  }

  try {
    const now = Date.now();
    if (now - lastAPICall < RATE_LIMIT_DELAY) {
      setTimeout(() => checkURL(url), RATE_LIMIT_DELAY);
      return;
    }

    lastAPICall = now;

    const response = await fetch(
      `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${url}`
    );
    
    const data = await response.json();
    
    SCAN_CACHE.set(url, {
      data: data,
      timestamp: Date.now()
    });

    chrome.storage.local.set({
      scanResult: {
        url: url,
        data: data
      }
    });

    updateBadge(data);
  } catch (error) {
    console.error('Error:', error);
  }
}

function updateBadge(data) {
  if (data.positives > 0) {
    chrome.browserAction.setBadgeText({text: '!'});
    chrome.browserAction.setBadgeBackgroundColor({color: '#d9534f'});
  } else {
    chrome.browserAction.setBadgeText({text: '✓'});
    chrome.browserAction.setBadgeBackgroundColor({color: '#5cb85c'});
  }
}

// Event listeners
chrome.tabs.onActivated.addListener((activeInfo) => {
  scanActiveTab();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    scanActiveTab();
  }
});