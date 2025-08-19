// Content script for Fountain Scan extension
// This script runs on every webpage to monitor content and detect potential scams

(function() {
  'use strict';
  
  let isAnalyzing = false;
  let lastAnalysisTime = 0;
  let observer = null;
  let analysisTimer = null;
  let settings = {
    blockingEnabled: false,
    alertsEnabled: true
  };
  
  // Throttle analysis to avoid excessive API calls
  const ANALYSIS_THROTTLE = 2000; // 2 seconds
  const CONTENT_CHANGE_DELAY = 1000; // 1 second delay after content changes
  
  // Load settings from storage
  function loadSettings() {
    if (chrome.storage) {
      chrome.storage.local.get(['settings'], (result) => {
        if (result.settings) {
          settings = { ...settings, ...result.settings };
        }
      });
    }
  }
  
  // Extract and clean page content
  function extractPageContent() {
    try {
      let textContent = '';
      
      // Priority content areas
      const prioritySelectors = [
        'title', 'h1', 'h2', 'h3', 
        '.title', '.headline', '.header',
        'meta[name="description"]',
        'meta[property="og:description"]'
      ];
      
      // Extract priority content first
      prioritySelectors.forEach(selector => {
        const elements = document.querySelectorAll(selector);
        elements.forEach(el => {
          if (el.tagName === 'META') {
            textContent += ' ' + (el.content || '');
          } else {
            textContent += ' ' + (el.textContent || '').trim();
          }
        });
      });
      
      // Get body text (filtered to avoid noise)
      const bodyText = document.body.innerText || '';
      const cleanBodyText = bodyText
        .replace(/\s+/g, ' ')
        .replace(/[\n\r\t]/g, ' ')
        .toLowerCase()
        .trim();
      
      // Combine and clean
      const fullContent = (textContent + ' ' + cleanBodyText)
        .toLowerCase()
        .replace(/\s+/g, ' ')
        .trim();
      
      return fullContent.substring(0, 5000); // Limit content size
      
    } catch (error) {
      console.error('FountainScan: Error extracting page content:', error);
      return '';
    }
  }
  
  // Comprehensive scan combining pattern detection and scoring
  function scanPageContent() {
    const content = extractPageContent();
    const pageTitle = document.title.toLowerCase();
    const url = window.location.href.toLowerCase();
    
    // Combined suspicious patterns
    const suspiciousPatterns = [
      // Nigerian/scholarship scam keywords
      'free scholarship', 'guaranteed scholarship', 'instant scholarship',
      'scholarship winner', 'congratulations scholarship', 'urgent scholarship',
      'congratulations you have won', 'nigerian scholarship winner',
      'scholarship processing fee', 'pay processing fee',
      
      // Identity/financial scams
      'enter your bvn', 'enter your nin', 'nin registration', 'bvn verification',
      'bank verification number', 'national identity number',
      'guaranteed loan', 'instant money', 'easy cash', 'work from home',
      'get rich quick', 'no collateral required', 'instant approval',
      
      // Government/recruitment scams
      'npower recruitment', 'jamb result', 'waec result',
      'federal government recruitment', 'ministry recruitment',
      
      // Urgency tactics
      'act now', 'limited time', 'expires today', 'last chance',
      'while supplies last', 'urgent action required', 'urgent scholarship application',
      'limited time scholarship', 'guaranteed scholarship approval'
    ];

    const foundPatterns = [];
    let suspiciousScore = 0;

    // Check for suspicious patterns in content and title
    suspiciousPatterns.forEach(pattern => {
      if (content.includes(pattern) || pageTitle.includes(pattern)) {
        foundPatterns.push(pattern);
        suspiciousScore += 2;
      }
    });

    // Check for suspicious form fields
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const inputs = form.querySelectorAll('input, select, textarea');
      inputs.forEach(input => {
        const placeholder = (input.placeholder || '').toLowerCase();
        const label = (input.labels?.[0]?.textContent || '').toLowerCase();
        const name = (input.name || '').toLowerCase();
        
        const sensitiveFields = [
          'nin', 'bvn', 'account number', 'routing number',
          'social security', 'credit card', 'cvv', 'pin',
          'mother maiden name', 'birth certificate'
        ];
        
        sensitiveFields.forEach(field => {
          if (placeholder.includes(field) || label.includes(field) || name.includes(field)) {
            foundPatterns.push(`Requests ${field}`);
            suspiciousScore += 3;
          }
        });
      });
    });

    // Check for suspicious external links
    const links = document.querySelectorAll('a[href^="http"]');
    let suspiciousLinks = 0;
    
    links.forEach(link => {
      const href = link.href.toLowerCase();
      const suspiciousDomains = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click'];
      
      if (suspiciousDomains.some(domain => href.includes(domain))) {
        suspiciousLinks++;
      }
    });
    
    if (suspiciousLinks > 3) {
      foundPatterns.push(`${suspiciousLinks} suspicious external links`);
      suspiciousScore += Math.min(suspiciousLinks, 10);
    }

    // Check for excessive urgency language
    const urgencyWords = ['urgent', 'hurry', 'limited', 'expires', 'deadline'];
    let urgencyCount = 0;
    
    urgencyWords.forEach(word => {
      const matches = (content.match(new RegExp(word, 'g')) || []).length;
      urgencyCount += matches;
    });
    
    if (urgencyCount > 10) {
      foundPatterns.push('Excessive urgency language');
      suspiciousScore += 2;
    }

    return {
      score: suspiciousScore,
      patterns: foundPatterns,
      isDangerous: suspiciousScore >= 8,
      isWarning: suspiciousScore >= 4,
      content: content,
      url: window.location.href,
      domain: window.location.hostname
    };
  }
  
  // Check if the current page should be analyzed
  function shouldAnalyzePage() {
    const skipProtocols = ['chrome:', 'chrome-extension:', 'moz-extension:', 'about:', 'data:'];
    const currentUrl = window.location.href.toLowerCase();
    
    if (skipProtocols.some(protocol => currentUrl.startsWith(protocol))) {
      return false;
    }
    
    const now = Date.now();
    if (isAnalyzing || (now - lastAnalysisTime) < ANALYSIS_THROTTLE) {
      return false;
    }
    
    const content = extractPageContent();
    return content.length >= 50;
  }
  
  // Show on-page notification
  function showPageNotification(scanResult) {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.fountainscan-notification');
    existingNotifications.forEach(n => n.remove());

    const isDangerous = scanResult.isDangerous;
    const isWarning = scanResult.isWarning;
    
    if (!isDangerous && !isWarning) return;

    const notification = document.createElement('div');
    notification.className = 'fountainscan-notification';
    
    const notificationColor = isDangerous ? '#e74c3c' : '#f39c12';
    const notificationIcon = isDangerous ? '🚨' : '⚠️';
    const notificationTitle = isDangerous ? 'Security Alert' : 'Security Warning';
    const notificationText = isDangerous 
      ? 'This site may be fraudulent or dangerous'
      : 'This site shows some suspicious characteristics';

    notification.innerHTML = `
      <div style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: white;
        border: 2px solid ${notificationColor};
        border-radius: 8px;
        padding: 15px;
        max-width: 350px;
        z-index: 999998;
        font-family: Arial, sans-serif;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        animation: slideIn 0.3s ease-out;
      ">
        <style>
          @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
          }
          @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
          }
        </style>
        <div style="display: flex; align-items: flex-start; gap: 10px;">
          <span style="font-size: 20px;">${notificationIcon}</span>
          <div style="flex: 1;">
            <h4 style="margin: 0 0 5px 0; color: ${notificationColor}; font-size: 14px;">
              ${notificationTitle}
            </h4>
            <p style="margin: 0 0 10px 0; color: #333; font-size: 13px; line-height: 1.4;">
              ${notificationText}
            </p>
            <div style="font-size: 11px; color: #666; margin-bottom: 10px;">
              Issues detected: ${scanResult.patterns.length}
            </div>
            <div style="display: flex; gap: 8px;">
              <button onclick="this.closest('.fountainscan-notification').style.animation='slideOut 0.3s ease-in'; setTimeout(() => this.closest('.fountainscan-notification').remove(), 300);" style="
                background: #6c757d;
                color: white;
                border: none;
                padding: 4px 8px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 11px;
              ">Dismiss</button>
              ${isDangerous ? `
                <button onclick="document.getElementById('fountainscan-details-${Date.now()}').style.display = document.getElementById('fountainscan-details-${Date.now()}').style.display === 'none' ? 'block' : 'none';" style="
                  background: ${notificationColor};
                  color: white;
                  border: none;
                  padding: 4px 8px;
                  border-radius: 4px;
                  cursor: pointer;
                  font-size: 11px;
                ">Details</button>
              ` : ''}
            </div>
            ${isDangerous ? `
              <div id="fountainscan-details-${Date.now()}" style="display: none; margin-top: 10px; padding: 8px; background: #f8f9fa; border-radius: 4px; font-size: 11px;">
                <strong>Detected issues:</strong><br>
                ${scanResult.patterns.slice(0, 3).join('<br>')}
                ${scanResult.patterns.length > 3 ? `<br><em>...and ${scanResult.patterns.length - 3} more</em>` : ''}
              </div>
            ` : ''}
          </div>
          <button onclick="this.closest('.fountainscan-notification').style.animation='slideOut 0.3s ease-in'; setTimeout(() => this.closest('.fountainscan-notification').remove(), 300);" style="
            background: none;
            border: none;
            font-size: 16px;
            cursor: pointer;
            color: #999;
            padding: 0;
            line-height: 1;
          ">×</button>
        </div>
        <div style="
          font-size: 10px;
          color: #999;
          text-align: right;
          margin-top: 8px;
          border-top: 1px solid #eee;
          padding-top: 5px;
        ">
          FountainScan Protection
        </div>
      </div>
    `;

    document.body.appendChild(notification);

    // Auto-dismiss after 10 seconds for warnings, 15 for dangerous sites
    const dismissTime = isDangerous ? 15000 : 10000;
    setTimeout(() => {
      if (document.body.contains(notification)) {
        notification.style.animation = 'slideOut 0.3s ease-in';
        setTimeout(() => {
          if (document.body.contains(notification)) {
            notification.remove();
          }
        }, 300);
      }
    }, dismissTime);
  }

  // Show warning overlay
  function showWarningOverlay(scanResult) {
    const existingOverlay = document.getElementById('fountainscan-overlay');
    if (existingOverlay) {
      existingOverlay.remove();
    }

    const overlay = document.createElement('div');
    overlay.id = 'fountainscan-overlay';
    overlay.innerHTML = `
      <div style="
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        z-index: 999999;
        display: flex;
        justify-content: center;
        align-items: center;
        font-family: Arial, sans-serif;
      ">
        <div style="
          background: white;
          padding: 30px;
          border-radius: 10px;
          max-width: 500px;
          text-align: center;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        ">
          <div style="font-size: 60px; color: #e74c3c; margin-bottom: 15px;">⚠️</div>
          <h2 style="color: #e74c3c; margin-bottom: 15px;">Security Warning</h2>
          <p style="margin-bottom: 20px; color: #333;">
            This website shows characteristics of a potential scam or fraudulent site.
          </p>
          <div style="
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            border-left: 4px solid #ffc107;
            text-align: left;
          ">
            <strong>Detected issues:</strong><br>
            ${scanResult.patterns.slice(0, 5).join('<br>')}
            ${scanResult.patterns.length > 5 ? `<br>... and ${scanResult.patterns.length - 5} more` : ''}
          </div>
          <div style="margin-top: 20px;">
            <button onclick="this.closest('#fountainscan-overlay').remove()" style="
              background: #28a745;
              color: white;
              border: none;
              padding: 10px 20px;
              margin: 5px;
              border-radius: 5px;
              cursor: pointer;
              font-size: 16px;
            ">Continue Anyway</button>
            <button onclick="window.history.back()" style="
              background: #dc3545;
              color: white;
              border: none;
              padding: 10px 20px;
              margin: 5px;
              border-radius: 5px;
              cursor: pointer;
              font-size: 16px;
            ">Go Back</button>
          </div>
          <p style="font-size: 12px; color: #666; margin-top: 15px;">
            Protected by FountainScan
          </p>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
  }
  
  // Main analysis function combining both approaches
  function analyzePageContent() {
    if (!shouldAnalyzePage()) {
      return;
    }
    
    isAnalyzing = true;
    lastAnalysisTime = Date.now();
    
    try {
      const scanResult = scanPageContent();
      
      // Send to background script for analysis
      chrome.runtime.sendMessage({
        type: 'PAGE_CONTENT',
        action: 'contentScanResult',
        ...scanResult,
        timestamp: Date.now()
      }).catch(error => {
        console.error('FountainScan: Error sending message to background script:', error);
      });
      
      // Handle threats with notifications
      if (scanResult.isDangerous || scanResult.isWarning) {
        // Send immediate threat notification for dangerous sites
        if (scanResult.isDangerous) {
          chrome.runtime.sendMessage({
            type: 'IMMEDIATE_THREAT',
            url: scanResult.url,
            threats: scanResult.patterns,
            timestamp: Date.now()
          }).catch(() => {});
        }
        
        if (settings.alertsEnabled && !window.location.href.includes('blocked.html')) {
          // Always show page notification for both warnings and dangerous sites
          setTimeout(() => showPageNotification(scanResult), 500);
          
          // Show modal overlay only for dangerous sites
          if (scanResult.isDangerous) {
            setTimeout(() => showWarningOverlay(scanResult), 1000);
          }
        }
      }
      
    } catch (error) {
      console.error('FountainScan: Error analyzing page content:', error);
    } finally {
      setTimeout(() => {
        isAnalyzing = false;
      }, 1000);
    }
  }
  
  // Debounced analysis function
  function debouncedAnalysis() {
    if (analysisTimer) {
      clearTimeout(analysisTimer);
    }
    
    analysisTimer = setTimeout(() => {
      analyzePageContent();
    }, CONTENT_CHANGE_DELAY);
  }
  
  // Set up mutation observer to detect content changes
  function setupContentObserver() {
    if (observer) {
      observer.disconnect();
    }
    
    observer = new MutationObserver((mutations) => {
      let significantChange = false;
      
      mutations.forEach(mutation => {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.TEXT_NODE) {
              const textContent = node.textContent || '';
              if (textContent.trim().length > 20) {
                significantChange = true;
              }
            }
          });
        }
      });
      
      if (significantChange) {
        debouncedAnalysis();
      }
    });
    
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: false
      });
    }
  }
  
  // Handle SPA navigation and URL changes
  function handleSPANavigation() {
    let currentUrl = window.location.href;
    
    const checkUrlChange = () => {
      if (window.location.href !== currentUrl) {
        currentUrl = window.location.href;
        setTimeout(() => {
          debouncedAnalysis();
        }, 1500);
      }
    };
    
    setInterval(checkUrlChange, 1000);
    
    window.addEventListener('popstate', () => {
      setTimeout(() => {
        debouncedAnalysis();
      }, 500);
    });
  }
  
  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
      case 'FORCE_SCAN':
        analyzePageContent();
        sendResponse({ success: true });
        break;
        
      case 'GET_PAGE_CONTENT':
        const content = extractPageContent();
        sendResponse({ content: content });
        break;
        
      default:
        sendResponse({ error: 'Unknown message type' });
    }
    
    return true;
  });
  
  // Initialize content script
  function initialize() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initialize);
      return;
    }
    
    try {
      loadSettings();
      
      // Perform initial analysis after a short delay
      setTimeout(() => {
        analyzePageContent();
      }, 1000);
      
      setupContentObserver();
      handleSPANavigation();
      
      console.log('FountainScan: Content script initialized for', window.location.hostname);
      
    } catch (error) {
      console.error('FountainScan: Error initializing content script:', error);
    }
  }
  
  // Handle page visibility and focus changes
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && shouldAnalyzePage()) {
      setTimeout(() => {
        debouncedAnalysis();
      }, 1000);
    }
  });
  
  window.addEventListener('focus', () => {
    setTimeout(() => {
      if (shouldAnalyzePage()) {
        debouncedAnalysis();
      }
    }, 500);
  });
  
  // Listen for settings updates
  if (chrome.storage) {
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.settings) {
        settings = { ...settings, ...changes.settings.newValue };
      }
    });
  }
  
  // Clean up on page unload
  window.addEventListener('beforeunload', () => {
    if (observer) {
      observer.disconnect();
    }
    if (analysisTimer) {
      clearTimeout(analysisTimer);
    }
  });
  
  // Start initialization
  initialize();
  
})();