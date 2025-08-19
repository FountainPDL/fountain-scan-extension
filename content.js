// Content script for Fountain Scan extension
// This script runs on every webpage to monitor content and detect potential scams

(function() {
  'use strict';
  
  let isAnalyzing = false;
  let lastAnalysisTime = 0;
  let observer = null;
  
  // Throttle analysis to avoid excessive API calls
  const ANALYSIS_THROTTLE = 2000; // 2 seconds
  const CONTENT_CHANGE_DELAY = 1000; // 1 second delay after content changes
  
  // Extract and clean page content
  function extractPageContent() {
    try {
      // Get visible text content
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
  
  // Check if the current page should be analyzed
  function shouldAnalyzePage() {
    // Skip certain pages/protocols
    const skipProtocols = ['chrome:', 'chrome-extension:', 'moz-extension:', 'about:', 'data:'];
    const currentUrl = window.location.href.toLowerCase();
    
    if (skipProtocols.some(protocol => currentUrl.startsWith(protocol))) {
      return false;
    }
    
    // Skip if already analyzing or recently analyzed
    const now = Date.now();
    if (isAnalyzing || (now - lastAnalysisTime) < ANALYSIS_THROTTLE) {
      return false;
    }
    
    // Skip if page has minimal content
    const content = extractPageContent();
    if (content.length < 50) {
      return false;
    }
    
    return true;
  }
  
  // Send page content for analysis
  function analyzePageContent() {
    if (!shouldAnalyzePage()) {
      return;
    }
    
    isAnalyzing = true;
    lastAnalysisTime = Date.now();
    
    try {
      const content = extractPageContent();
      const url = window.location.href;
      
      // Send to background script for analysis
      chrome.runtime.sendMessage({
        type: 'PAGE_CONTENT',
        url: url,
        content: content,
        domain: window.location.hostname,
        timestamp: Date.now()
      }).catch(error => {
        console.error('FountainScan: Error sending message to background script:', error);
      });
      
    } catch (error) {
      console.error('FountainScan: Error analyzing page content:', error);
    } finally {
      // Reset analyzing flag after a delay
      setTimeout(() => {
        isAnalyzing = false;
      }, 1000);
    }
  }
  
  // Debounced analysis function
  let analysisTimer = null;
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
      
      // Check if mutations indicate significant content changes
      mutations.forEach(mutation => {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          // Check if added nodes contain substantial text content
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
    
    // Observe changes to the document body
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: false // Don't track text changes to avoid noise
      });
    }
  }
  
  // Handle dynamic content loading (SPA support)
  function handleSPANavigation() {
    // Listen for URL changes in Single Page Applications
    let currentUrl = window.location.href;
    
    const checkUrlChange = () => {
      if (window.location.href !== currentUrl) {
        currentUrl = window.location.href;
        // URL changed, re-analyze after a delay
        setTimeout(() => {
          debouncedAnalysis();
        }, 1500);
      }
    };
    
    // Monitor URL changes
    setInterval(checkUrlChange, 1000);
    
    // Listen for popstate events (browser back/forward)
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
    
    return true; // Keep message channel open
  });
  
  // Enhanced quick scan for immediate threat detection
  function performQuickScan() {
    const content = extractPageContent();
    const url = window.location.href.toLowerCase();
    
    // High-risk keywords that trigger immediate alerts
    const immediateThreats = [
      'congratulations you have won',
      'nigerian scholarship winner',
      'enter your bvn',
      'enter your nin',
      'pay processing fee',
      'scholarship processing fee',
      'urgent scholarship application',
      'limited time scholarship',
      'guaranteed scholarship approval'
    ];
    
    const foundThreats = immediateThreats.filter(threat => 
      content.includes(threat) || url.includes(threat.replace(/\s+/g, '-'))
    );
    
    if (foundThreats.length > 0) {
      // Immediate high-risk detection
      chrome.runtime.sendMessage({
        type: 'IMMEDIATE_THREAT',
        url: window.location.href,
        threats: foundThreats,
        timestamp: Date.now()
      }).catch(error => {
        console.error('FountainScan: Error sending immediate threat alert:', error);
      });
    }
  }
  
  // Initialize content script
  function initialize() {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initialize);
      return;
    }
    
    try {
      // Perform initial quick scan
      performQuickScan();
      
      // Perform initial analysis after a short delay
      setTimeout(() => {
        analyzePageContent();
      }, 1000);
      
      // Set up content observer
      setupContentObserver();
      
      // Set up SPA navigation handling
      handleSPANavigation();
      
      console.log('FountainScan: Content script initialized for', window.location.hostname);
      
    } catch (error) {
      console.error('FountainScan: Error initializing content script:', error);
    }
  }
  
  // Handle page visibility changes
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && shouldAnalyzePage()) {
      // Page became visible, re-analyze after delay
      setTimeout(() => {
        debouncedAnalysis();
      }, 1000);
    }
  });
  
  // Handle focus events (user returned to tab)
  window.addEventListener('focus', () => {
    setTimeout(() => {
      if (shouldAnalyzePage()) {
        debouncedAnalysis();
      }
    }, 500);
  });
  
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