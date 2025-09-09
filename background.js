// FOUNTAIN SCAN CHROME EXTENSION - BACKGROUND SERVICE WORKER

// CONSTANTS AND CONFIGURATION
const RULE_WEIGHTS = {
  https: 10,
  domainAge: 15,
  blacklistHit: 70,
  keyword: 10,
  suspiciousTld: 15,
  urlShortener: 10
};

// Nigerian-specific keyword patterns
const NIGERIAN_SCAM_PATTERNS = {
  scholarship: ['free-scholarship', 'guaranteed-scholarship', 'instant-scholarship', 'scholarship-winner'],
  financial: ['instant-money', 'guaranteed-loan', 'easy-cash', 'quick-loan', 'nin', 'bvn'],
  government: ['npower', 'jamb-result', 'waec-result', 'inec-recruitment', 'nnpc-recruitment'],
  urgency: ['urgent', 'limited-time', 'expires-soon', 'act-now', 'deadline-today']
};

const SUSPICIOUS_PATTERNS = [
  'verify-account', 'update-information', 'confirm-identity',
  'security-alert', 'account-suspended', 'click-here-now',
  'work-from-home', 'get-rich-quick', 'Bank-Verification-Number',
  'payment-verification'
];

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link'];

// GLOBAL STATE
let settings = {
  theme: 'light',
  alertsEnabled: true,
  blockingEnabled: false,
  systemLang: 'en-NG',
  alertLang: 'en'
};

let blacklist = [];
let whitelist = [];
let notificationStates = new Map(); // Track notification states per tab

// UTILITY FUNCTIONS
function cleanDomain(domain) {
  return domain.replace(/^(https?:\/\/)?(www\.)?/, '').toLowerCase();
}

function domainMatches(currentDomain, listDomain) {
  const cleanCurrent = cleanDomain(currentDomain);
  const cleanList = cleanDomain(listDomain);

  if (cleanCurrent === cleanList) return true; // Exact match
  if (cleanCurrent.endsWith('.' + cleanList)) return true; // Subdomain match
  
  if (cleanList.startsWith('*.')) { // Wildcard support
    const baseDomain = cleanList.substring(2);
    return cleanCurrent.endsWith('.' + baseDomain) || cleanCurrent === baseDomain;
  }

  return false;
}

function shouldBlockDomain(domain) {
  if (!settings.blockingEnabled) return false;
  if (whitelist.some(d => domainMatches(domain, d))) return false; // Don't block if whitelisted
  return blacklist.some(d => domainMatches(domain, d)); // Block if blacklisted
}

function scanUrlForPatterns(url) {
  const allPatterns = [
    ...Object.values(NIGERIAN_SCAM_PATTERNS).flat(),
    ...SUSPICIOUS_PATTERNS
  ];

  const lowerUrl = url.toLowerCase();
  let score = 0;
  const foundPatterns = [];

  allPatterns.forEach(pattern => {
    if (lowerUrl.includes(pattern)) {
      score += 2;
      foundPatterns.push(pattern);
    }
  });

  return {
    score,
    foundPatterns,
    isDangerous: score >= 4
  };
}

// STORAGE OPERATIONS
async function loadStoredData() {
  try {
    const result = await chrome.storage.local.get(['settings', 'blacklist', 'whitelist']);
    if (result.settings) settings = { ...settings, ...result.settings };
    if (result.blacklist) blacklist = result.blacklist;
    if (result.whitelist) whitelist = result.whitelist;

    await updateBlockingRules();
  } catch (error) {
    console.error('Error loading stored data:', error);
  }
}

async function saveToStorage(key, value) {
  try {
    await chrome.storage.local.set({ [key]: value });
  } catch (error) {
    console.error(`Error saving ${key}:`, error);
  }
}

// SECURITY ANALYSIS ENGINE
async function calculateHeuristicScore(url, content, domain) {
  let score = 0;
  const detectedIssues = [];

  try {
    if (!url.startsWith("https://")) { // HTTPS Check
      score += RULE_WEIGHTS.https;
      detectedIssues.push('No HTTPS encryption');
    }

    const suspiciousTld = SUSPICIOUS_TLDS.find(tld => domain.endsWith(tld)); // Suspicious TLD Check
    if (suspiciousTld) {
      score += RULE_WEIGHTS.suspiciousTld;
      detectedIssues.push(`Suspicious domain extension: ${suspiciousTld}`);
    }

    if (URL_SHORTENERS.some(shortener => domain.includes(shortener))) { // URL Shortener Check
      score += RULE_WEIGHTS.urlShortener;
      detectedIssues.push('URL shortener detected');
    }

    if (blacklist.some(d => domainMatches(domain, d))) { // Check against blacklist
      score += RULE_WEIGHTS.blacklistHit;
      detectedIssues.push('Domain is blacklisted');
    }

    if (whitelist.some(d => domainMatches(domain, d))) { // Check against whitelist (override other checks)
      return { score: 0, status: 'safe', issues: ['Domain is whitelisted'] };
    }

    const lowerContent = content.toLowerCase(); // Nigerian-specific keyword detection
    const lowerUrl = url.toLowerCase();

    Object.entries(NIGERIAN_SCAM_PATTERNS).forEach(([category, keywords]) => {
      const foundKeywords = keywords.filter(keyword => 
        lowerContent.includes(keyword) || lowerUrl.includes(keyword)
      );

      if (foundKeywords.length > 0) {
        const keywordScore = foundKeywords.length * RULE_WEIGHTS.keyword;
        score += keywordScore;
        detectedIssues.push(`${category} scam indicators: ${foundKeywords.join(', ')}`);
      }
    });

    const foundSuspicious = SUSPICIOUS_PATTERNS.filter(pattern => // Additional suspicious patterns
      lowerContent.includes(pattern) || lowerUrl.includes(pattern)
    );

    if (foundSuspicious.length > 0) {
      score += foundSuspicious.length * 3;
      detectedIssues.push(`Phishing indicators: ${foundSuspicious.join(', ')}`);
    }

  } catch (error) {
    console.error('Error calculating heuristic score:', error);
    detectedIssues.push('Error during analysis');
  }

  let status = 'safe'; // Determine status based on score
  if (score >= 70) status = 'danger';
  else if (score >= 40) status = 'warning';

  return { score, status, issues: detectedIssues };
}

// NOTIFICATION SYSTEM
async function showNotification(domain, analysis, tabId) {
  if (analysis.status === 'safe') return;

  // Check if notifications are disabled for this tab
  const notificationKey = `${tabId}_${domain}`;
  if (notificationStates.get(notificationKey) === 'disabled') {
    return;
  }

  const notificationId = `fountain_scan_${Date.now()}`;
  const iconMap = {
    danger: 'icons/danger.png',
    warning: 'icons/warning.png'
  };

  const getRiskLevel = (status, score) => { // Dynamic messages based on actual risk level
    if (status === 'danger' || score >= 70) return 'HIGH RISK';
    if (status === 'warning' || score >= 40) return 'MODERATE RISK';
    return 'LOW RISK';
  };

  const riskLevel = getRiskLevel(analysis.status, analysis.score);
  const message = `${riskLevel}: ${domain} - Score: ${analysis.score}/100`;

  try {
    await chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: iconMap[analysis.status] || 'icons/icon128.png',
      title: 'Fountain Scan Security Alert',
      message: message,
      contextMessage: analysis.issues.slice(0, 2).join(', '),
      priority: analysis.status === 'danger' ? 2 : 1
    });

    setTimeout(() => chrome.notifications.clear(notificationId), 10000); // Auto-clear notification after 10 seconds

  } catch (error) {
    console.error('Error showing notification:', error);
  }
}

async function showSecurityWarning(message) {
  const { domain, score, tabId, issues } = message;

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: (domain, score, issues) => {
        const existing = document.getElementById('fountain-scan-warning'); // Remove existing warnings
        if (existing) existing.remove();

        const overlay = document.createElement('div'); // Create warning overlay
        overlay.id = 'fountain-scan-warning';
        overlay.innerHTML = `
          <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
                      background: rgba(0,0,0,0.8); z-index: 999999; display: flex; 
                      align-items: center; justify-content: center;">
            <div style="background: white; padding: 20px; border-radius: 10px; 
                        max-width: 400px; text-align: center; box-shadow: 0 4px 20px rgba(0,0,0,0.3);">
              <h2 style="color: #d32f2f; margin: 0 0 15px 0;">⚠️ Security Warning</h2>
              <p><strong>Domain:</strong> ${domain}</p>
              <p><strong>Risk Score:</strong> ${score}/100</p>
              <p><strong>Detected Issues:</strong> ${issues.join(', ')}</p>
              <p style="margin: 15px 0;">This website may be attempting to scam you. 
                 Nigerian students are frequently targeted with fake scholarship offers.</p>
              <div style="margin-top: 20px;">
                <button id="fountain-continue" style="background: #f44336; color: white; 
                        border: none; padding: 10px 20px; margin: 5px; border-radius: 5px; cursor: pointer;">
                  Continue Anyway
                </button>
                <button id="fountain-goback" style="background: #4caf50; color: white; 
                        border: none; padding: 10px 20px; margin: 5px; border-radius: 5px; cursor: pointer;">
                  Go Back to Safety
                </button>
              </div>
            </div>
          </div>
        `;

        document.body.appendChild(overlay);

        document.getElementById('fountain-continue').onclick = () => { // Handle button clicks
          overlay.remove();
          // Signal to disable further notifications for this tab/domain
          chrome.runtime.sendMessage({
            type: 'DISABLE_NOTIFICATIONS',
            tabId: window.location.href,
            domain: domain
          });
        };
        document.getElementById('fountain-goback').onclick = () => history.back();
      },
      args: [domain, score, issues]
    });

  } catch (error) {
    console.error('Error showing security warning:', error);
  }
}

// BLOCKING SYSTEM
async function updateBlockingRules() {
  if (!chrome.declarativeNetRequest) {
    console.log('Declarative Net Request API not available');
    return;
  }

  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules(); // Clear existing rules
    const ruleIdsToRemove = existingRules.map(rule => rule.id);

    if (ruleIdsToRemove.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: ruleIdsToRemove
      });
    }

    if (!settings.blockingEnabled || blacklist.length === 0) return; // Add new blocking rules if blocking is enabled

    const newRules = [];

    blacklist.forEach((domain, index) => {
      if (whitelist.some(d => domainMatches(domain, d))) return; // Skip if domain is whitelisted

      const cleanedDomain = cleanDomain(domain);
      let urlFilter;

      if (cleanedDomain.startsWith('*.')) {
        const baseDomain = cleanedDomain.substring(2);
        urlFilter = `*://*.${baseDomain}/*`;
      } else {
        urlFilter = `*://${cleanedDomain}/*`;
      }

      newRules.push({ // Main rule
        id: index + 1,
        priority: 1,
        action: {
          type: 'redirect',
          redirect: {
            extensionPath: '/blocked.html?url=' + encodeURIComponent(domain) + '&reason_flagged=' + encodeURIComponent('Domain is blacklisted')
          }
        },
        condition: {
          urlFilter: urlFilter,
          resourceTypes: ['main_frame']
        }
      });

      if (!cleanedDomain.startsWith('*.')) { // WWW variant
        newRules.push({
          id: index + 1000,
          priority: 1,
          action: {
            type: 'redirect',
            redirect: {
              extensionPath: '/blocked.html?url=' + encodeURIComponent(domain) + '&reason_flagged=' + encodeURIComponent('Domain is blacklisted')
            }
          },
          condition: {
            urlFilter: `*://www.${cleanedDomain}/*`,
            resourceTypes: ['main_frame']
          }
        });
      }
    });

    if (newRules.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: newRules
      });
    }

    console.log('Blocking rules updated successfully');
  } catch (error) {
    console.error('Error updating blocking rules:', error);
  }
}

async function handleTabBlocking(url, reason_flagged) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();

    if (!blacklist.some(d => domainMatches(domain, d))) { // Add to blacklist if not already there
      blacklist.push(domain);
      await saveToStorage('blacklist', blacklist);
    }

    await updateBlockingRules();

    const tabs = await chrome.tabs.query({ active: true, currentWindow: true }); // Find and redirect current tab
    if (tabs[0]) {
      const blockingUrl = chrome.runtime.getURL('blocked.html') + 
        `?url=${encodeURIComponent(url)}&reason_flagged=${encodeURIComponent(reason_flagged)}`;

      await chrome.tabs.update(tabs[0].id, { url: blockingUrl });
    }

  } catch (error) {
    console.error('Error blocking tab:', error);
  }
}

// MESSAGE HANDLERS
async function handlePageContent(message, sender) {
  const { url, content } = message;
  const domain = new URL(url).hostname;

  const analysis = await calculateHeuristicScore(url, content, domain); // Calculate risk score

  if (settings.alertsEnabled && analysis.status !== 'safe') { // Show notification if alerts are enabled
    await showNotification(domain, analysis, sender.tab.id);
  }

  if (settings.blockingEnabled && analysis.status === 'danger' && sender.tab) { // Handle blocking if enabled and site is dangerous
    const reasonForBlocking = `Dangerous site detected - Score: ${analysis.score} - Issues: ${analysis.issues.join(', ')}`;
    await handleTabBlocking(url, reasonForBlocking);
  }

  await saveToStorage(`scan_${sender.tab.id}`, { // Store scan result for popup access
    url,
    domain,
    analysis,
    timestamp: Date.now()
  });
}

async function handleManualScan(message) {
  const { url } = message;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error('No active tab found');

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => document.body.innerText.toLowerCase()
    });

    const content = results[0]?.result || '';
    const domain = new URL(url).hostname;
    const analysis = await calculateHeuristicScore(url, content, domain);

    return { success: true, analysis };

  } catch (error) {
    console.error('Manual scan error:', error);
    return { success: false, error: error.message };
  }
}

async function handleAddToWhitelist(domain, originalUrl) {
  try {
    if (!whitelist.some(d => d.toLowerCase() === domain.toLowerCase())) {
      whitelist.push(domain);
    }

    const blacklistIndex = blacklist.findIndex(d => d.toLowerCase() === domain.toLowerCase()); // Remove from blacklist if present
    if (blacklistIndex > -1) {
      blacklist.splice(blacklistIndex, 1);
    }

    await saveToStorage('whitelist', whitelist);
    await saveToStorage('blacklist', blacklist);
    await updateBlockingRules();

    return true;
  } catch (error) {
    console.error('Error adding to whitelist:', error);
    return false;
  }
}

async function handleFalsePositiveReport(url, reason_flagged) {
  try {
    console.log('False positive report:', { url, reason_flagged, timestamp: new Date().toISOString() });
    return true; // Here you could send to your backend API
  } catch (error) {
    console.error('Error reporting false positive:', error);
    return false;
  }
}

// EVENT LISTENERS
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  try {
    switch (message.type || message.action) {
      case 'PAGE_CONTENT':
        await handlePageContent(message, sender);
        break;

      case 'MANUAL_SCAN':
        const result = await handleManualScan(message);
        sendResponse(result);
        break;

      case 'SHOW_WARNING':
        await showSecurityWarning(message);
        break;

      case 'DISABLE_NOTIFICATIONS':
        const notificationKey = `${sender.tab?.id}_${message.domain}`;
        notificationStates.set(notificationKey, 'disabled');
        break;

      case 'updateSettings':
      case 'updateBlockingRules':
        settings = message.settings || settings;
        blacklist = message.blacklist || blacklist;
        whitelist = message.whitelist || whitelist;
        await updateBlockingRules();
        break;

      case 'blockCurrentTab':
        await handleTabBlocking(message.url, message.reason_flagged);
        break;

      case 'addToWhitelist':
        const success = await handleAddToWhitelist(message.domain, message.url);
        sendResponse({ success });
        break;

      case 'reportFalsePositive':
        const reported = await handleFalsePositiveReport(message.url, message.reason_flagged);
        sendResponse({ success: reported });
        break;

      default:
        console.log('Unknown message type:', message.type || message.action);
    }
  } catch (error) {
    console.error('Error handling message:', error);
    sendResponse({ error: error.message });
  }

  return true; // Keep message channel open for async response
});

chrome.notifications.onClicked.addListener(async (notificationId) => {
  if (notificationId.startsWith('fountain_scan_')) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) await chrome.tabs.update(tab.id, { active: true });
    } catch (error) {
      console.error('Error handling notification click:', error);
    }
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url && settings.blockingEnabled) {
    try {
      const urlObj = new URL(tab.url);
      const domain = urlObj.hostname.toLowerCase();

      if (shouldBlockDomain(domain)) {
        const blockingUrl = chrome.runtime.getURL('blocked.html') + 
          `?url=${encodeURIComponent(tab.url)}&reason_flagged=${encodeURIComponent('Domain is blacklisted')}`;

        await chrome.tabs.update(tabId, { url: blockingUrl });
      }
    } catch (error) {
      // Invalid URL or other error - ignore
    }
  }
});

// Clear notification states when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  for (const [key] of notificationStates.entries()) {
    if (key.startsWith(`${tabId}_`)) {
      notificationStates.delete(key);
    }
  }
});

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (settings.blockingEnabled && details.type === 'main_frame') {
      try {
        const urlObj = new URL(details.url);
        const domain = urlObj.hostname.toLowerCase();

        if (whitelist.some(d => domainMatches(domain, d))) return {}; // Skip if whitelisted

        const scanResult = scanUrlForPatterns(details.url); // Quick scan for dangerous patterns

        if (scanResult.isDangerous) {
          if (!blacklist.some(d => domainMatches(domain, d))) { // Add to blacklist and block
            blacklist.push(domain);
            saveToStorage('blacklist', blacklist);
            updateBlockingRules();
          }

          const reasonForBlocking = `Suspicious patterns detected: ${scanResult.foundPatterns.join(', ')}`;
          const blockingUrl = chrome.runtime.getURL('blocked.html') + 
            `?url=${encodeURIComponent(details.url)}&reason_flagged=${encodeURIComponent(reasonForBlocking)}`;

          return { redirectUrl: blockingUrl };
        }
      } catch (error) {
        console.error('Error in web request listener:', error);
      }
    }

    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

// Initialize on startup
chrome.runtime.onStartup.addListener(loadStoredData);
chrome.runtime.onInstalled.addListener(loadStoredData);