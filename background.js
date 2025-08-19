// Background service worker for Chrome extension
const RULE_WEIGHTS = {
  https: 10,
  domainAge: 15,
  blacklistHit: 70,
  keyword: 10,
  suspiciousTld: 15,
  urlShortener: 10
};

// Nigerian-specific keyword patterns with weights
const NIGERIAN_SCAM_PATTERNS = {
  scholarship: ['free-scholarship', 'guaranteed-scholarship', 'instant-scholarship', 'scholarship-winner'],
  financial: ['instant-money', 'guaranteed-loan', 'easy-cash', 'quick-loan', 'nin', 'bvn'],
  government: ['npower', 'jamb-result', 'waec-result', 'inec-recruitment', 'nnpc-recruitment'],
  urgency: ['urgent', 'limited-time', 'expires-soon', 'act-now', 'deadline-today']
};

// Enhanced heuristic scoring system
async function calculateHeuristicScore(url, content, domain) {
  let score = 0;
  const detectedIssues = [];

  try {
    // 1. HTTPS Check
    if (!url.startsWith("https://")) {
      score += RULE_WEIGHTS.https;
      detectedIssues.push('No HTTPS encryption');
    }

    // 2. Suspicious TLD Check
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click'];
    const suspiciousTld = suspiciousTlds.find(tld => domain.endsWith(tld));
    if (suspiciousTld) {
      score += RULE_WEIGHTS.suspiciousTld;
      detectedIssues.push(`Suspicious domain extension: ${suspiciousTld}`);
    }

    // 3. URL Shortener Check
    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link'];
    if (shorteners.some(shortener => domain.includes(shortener))) {
      score += RULE_WEIGHTS.urlShortener;
      detectedIssues.push('URL shortener detected');
    }

    // 4. Check against stored blacklist
    const storage = await chrome.storage.local.get(['blacklist']);
    const blacklist = storage.blacklist || [];
    
    const isBlacklisted = blacklist.some(blacklistedDomain => {
      const cleanBlacklisted = blacklistedDomain.toLowerCase().replace(/^(www\.)?/, '');
      const cleanCurrent = domain.toLowerCase().replace(/^(www\.)?/, '');
      return cleanCurrent === cleanBlacklisted || 
             cleanCurrent.endsWith('.' + cleanBlacklisted);
    });

    if (isBlacklisted) {
      score += RULE_WEIGHTS.blacklistHit;
      detectedIssues.push('Domain is blacklisted');
    }

    // 5. Check against whitelist (override other checks)
    const whitelistStorage = await chrome.storage.local.get(['whitelist']);
    const whitelist = whitelistStorage.whitelist || [];
    
    const isWhitelisted = whitelist.some(whitelistedDomain => {
      const cleanWhitelisted = whitelistedDomain.toLowerCase().replace(/^(www\.)?/, '');
      const cleanCurrent = domain.toLowerCase().replace(/^(www\.)?/, '');
      
      // Support wildcards
      if (cleanWhitelisted.startsWith('*.')) {
        const baseDomain = cleanWhitelisted.substring(2);
        return cleanCurrent.endsWith('.' + baseDomain) || cleanCurrent === baseDomain;
      }
      
      return cleanCurrent === cleanWhitelisted || 
             cleanCurrent.endsWith('.' + cleanWhitelisted);
    });

    if (isWhitelisted) {
      return { score: 0, status: 'safe', issues: ['Domain is whitelisted'] };
    }

    // 6. Nigerian-specific keyword detection
    const lowerContent = content.toLowerCase();
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

    // 7. Additional suspicious patterns
    const suspiciousPatterns = [
      'verify-account', 'update-information', 'confirm-identity',
      'security-alert', 'account-suspended', 'click-here-now'
    ];
    
    const foundSuspicious = suspiciousPatterns.filter(pattern => 
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

  // Determine status based on score
  let status = 'safe';
  if (score >= 70) {
    status = 'danger';
  } else if (score >= 40) {
    status = 'warning';
  }

  return { score, status, issues: detectedIssues };
}

// Handle messages from content script and popup
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  try {
    switch (message.type) {
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
        
      default:
        console.log('Unknown message type:', message.type);
    }
  } catch (error) {
    console.error('Error handling message:', error);
    sendResponse({ error: error.message });
  }
  
  return true; // Keep message channel open for async response
});

// Handle page content analysis
async function handlePageContent(message, sender) {
  const { url, content } = message;
  const domain = new URL(url).hostname;
  
  // Calculate risk score
  const analysis = await calculateHeuristicScore(url, content, domain);
  
  // Get user settings
  const settings = await chrome.storage.local.get(['settings']);
  const userSettings = settings.settings || { alertsEnabled: true, blockingEnabled: false };
  
  // Show notification if alerts are enabled
  if (userSettings.alertsEnabled && analysis.status !== 'safe') {
    await showNotification(domain, analysis);
  }
  
  // Handle blocking if enabled and site is dangerous
  if (userSettings.blockingEnabled && analysis.status === 'danger' && sender.tab) {
    await handleBlocking(sender.tab.id, domain, analysis);
  }
  
  // Store scan result for popup access
  await chrome.storage.local.set({
    [`scan_${sender.tab.id}`]: {
      url,
      domain,
      analysis,
      timestamp: Date.now()
    }
  });
}

// Handle manual scan request from popup
async function handleManualScan(message) {
  const { url } = message;
  
  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error('No active tab found');
    
    // Get page content
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => document.body.innerText.toLowerCase()
    });
    
    const content = results[0]?.result || '';
    const domain = new URL(url).hostname;
    
    // Perform analysis
    const analysis = await calculateHeuristicScore(url, content, domain);
    
    return { success: true, analysis };
    
  } catch (error) {
    console.error('Manual scan error:', error);
    return { success: false, error: error.message };
  }
}

// Show security notification
async function showNotification(domain, analysis) {
  const notificationId = `fountain_scan_${Date.now()}`;
  
  let title = 'Fountain Scan Security Alert';
  let message = '';
  let iconUrl = 'icons/icon128.png';
  
  switch (analysis.status) {
    case 'danger':
      message = `HIGH RISK: ${domain} - Score: ${analysis.score}`;
      iconUrl = 'icons/danger.png';
      break;
    case 'warning':
      message = `SUSPICIOUS: ${domain} - Score: ${analysis.score}`;
      iconUrl = 'icons/warning.png';
      break;
    default:
      return; // Don't show notification for safe sites
  }
  
  try {
    await chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: iconUrl,
      title: title,
      message: message,
      contextMessage: analysis.issues.slice(0, 2).join(', '), // Show first 2 issues
      priority: analysis.status === 'danger' ? 2 : 1
    });
    
    // Auto-clear notification after 10 seconds
    setTimeout(() => {
      chrome.notifications.clear(notificationId);
    }, 10000);
    
  } catch (error) {
    console.error('Error showing notification:', error);
  }
}

// Handle security warning display
async function showSecurityWarning(message) {
  const { domain, score, tabId } = message;
  
  try {
    // Inject warning overlay into the page
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: (domain, score) => {
        // Remove existing warnings
        const existing = document.getElementById('fountain-scan-warning');
        if (existing) existing.remove();
        
        // Create warning overlay
        const overlay = document.createElement('div');
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
        
        // Handle button clicks
        document.getElementById('fountain-continue').onclick = () => overlay.remove();
        document.getElementById('fountain-goback').onclick = () => history.back();
        
      },
      args: [domain, score]
    });
    
  } catch (error) {
    console.error('Error showing security warning:', error);
  }
}

// Handle site blocking
async function handleBlocking(tabId, domain, analysis) {
  try {
    // Log the blocking action
    console.log(`Blocking dangerous site: ${domain} (Score: ${analysis.score})`);
    
    // Replace the page with a block page
    await chrome.tabs.update(tabId, {
      url: chrome.runtime.getURL('blocked.html') + '?domain=' + encodeURIComponent(domain) + '&score=' + analysis.score
    });
    
  } catch (error) {
    console.error('Error blocking site:', error);
    // Fallback: close the tab
    try {
      await chrome.tabs.remove(tabId);
    } catch (closeError) {
      console.error('Error closing tab:', closeError);
    }
  }
}

// Handle notification clicks
chrome.notifications.onClicked.addListener(async (notificationId) => {
  if (notificationId.startsWith('fountain_scan_')) {
    // Open popup or focus on the problematic tab
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        await chrome.tabs.update(tab.id, { active: true });
      }
    } catch (error) {
      console.error('Error handling notification click:', error);
    }
  }
});

// Clean up old scan results periodically
setInterval(async () => {
  try {
    const storage = await chrome.storage.local.get();
    const keysToRemove = [];
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    
    Object.entries(storage).forEach(([key, value]) => {
      if (key.startsWith('scan_') && value.timestamp && value.timestamp < oneHourAgo) {
        keysToRemove.push(key);
      }
    });
    
    if (keysToRemove.length > 0) {
      await chrome.storage.local.remove(keysToRemove);
      console.log(`Cleaned up ${keysToRemove.length} old scan results`);
    }
  } catch (error) {
    console.error('Error cleaning up old scan results:', error);
  }
}, 60 * 60 * 1000); // Run every hour

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  console.log('Fountain Scan extension installed/updated');
  
  // Set default settings if not exists
  const storage = await chrome.storage.local.get(['settings']);
  if (!storage.settings) {
    await chrome.storage.local.set({
      settings: {
        theme: 'light',
        alertsEnabled: true,
        blockingEnabled: false,
        systemLang: 'en-NG',
        alertLang: 'en'
      }
    });
  }
});