// blocked.js - Handles blocked.html UI and actions for FountainScan

// Variables from the original HTML script
let blockedUrl = '';
let blockedreason_flagged = '';

// Utility functions from the original HTML script
function getUrlParameter(name) {
    name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
    const regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
    const results = regex.exec(location.search);
    return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
}

function showStatusMessage(message, type = 'info') {
    const container = document.getElementById('status-container');
    const statusDiv = document.createElement('div');
    statusDiv.className = `status-message status-${type}`;
    statusDiv.textContent = message;

    container.innerHTML = '';
    container.appendChild(statusDiv);

    // Auto-hide after 5 seconds
    setTimeout(() => {
        if (statusDiv.parentNode) {
            statusDiv.remove();
        }
    }, 5000);
}

function setButtonLoading(buttonId, isLoading) {
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = isLoading;
        if (isLoading) {
            button.dataset.originalText = button.textContent;
            button.textContent = 'Loading...';
        } else {
            if (button.dataset.originalText) {
                button.textContent = button.dataset.originalText;
                delete button.dataset.originalText;
            }
        }
    }
}

function isExtensionContext() {
    return typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id;
}

function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname.replace(/^www\./, '');
    } catch (error) {
        console.error('Error extracting domain:', error);
        return url;
    }
}

// Button handlers from the original HTML script
function handleGoBack() {
    try {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            // Fallback options
            if (window.opener) {
                window.close();
            } else {
                window.location.href = 'about:blank';
            }
        }
    } catch (error) {
        console.error('Error going back:', error);
        showStatusMessage('Unable to go back. Please use your browser\'s back button.', 'error');
    }
}

function handleAddToWhitelist() {
    if (!blockedUrl) {
        showStatusMessage('No URL to whitelist', 'error');
        return;
    }

    setButtonLoading('whitelist-btn', true);

    if (isExtensionContext()) {
        try {
            const domain = extractDomain(blockedUrl);

            chrome.runtime.sendMessage({
                action: 'addToWhitelist',
                domain: domain,
                url: blockedUrl
            }, function(response) {
                setButtonLoading('whitelist-btn', false);

                if (chrome.runtime.lastError) {
                    console.error('Chrome runtime error:', chrome.runtime.lastError);
                    showStatusMessage('Extension error. Please try using the extension popup.', 'error');
                    return;
                }

                if (response && response.success) {
                    showStatusMessage('Site added to whitelist! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = blockedUrl;
                    }, 2000);
                } else {
                    showStatusMessage('Failed to add site to whitelist. Please use the extension popup.', 'error');
                }
            });
        } catch (error) {
            setButtonLoading('whitelist-btn', false);
            console.error('Error adding to whitelist:', error);
            showStatusMessage('Error processing request. Please use the extension popup.', 'error');
        }
    } else {
        setButtonLoading('whitelist-btn', false);
        showStatusMessage('Extension not detected. Please use the extension popup to whitelist sites.', 'info');
    }
}

function handleOpenSettings() {
    if (isExtensionContext()) {
        try {
            if (chrome.runtime.openOptionsPage) {
                chrome.runtime.openOptionsPage();
                showStatusMessage('Opening extension settings...', 'info');
            } else {
                showStatusMessage('Please right-click the extension icon and select "Options"', 'info');
            }
        } catch (error) {
            console.error('Error opening settings:', error);
            showStatusMessage('Please click the Fountain Scan extension icon to access settings.', 'info');
        }
    } else {
        showStatusMessage('Please click the Fountain Scan extension icon in your browser toolbar to access settings.', 'info');
    }
}

function handleReportSite() {
    if (!blockedUrl) {
        showStatusMessage('No URL to report', 'error');
        return;
    }

    setButtonLoading('report-btn', true);

    if (isExtensionContext()) {
        try {
            chrome.runtime.sendMessage({
                action: 'reportFalsePositive',
                url: blockedUrl,
                reason_flagged: 'User reported as false positive',
                timestamp: new Date().toISOString()
            }, function(response) {
                setButtonLoading('report-btn', false);

                if (chrome.runtime.lastError) {
                    console.error('Chrome runtime error:', chrome.runtime.lastError);
                    showStatusMessage('Extension error. Please try using the extension popup.', 'error');
                    return;
                }

                if (response && response.success) {
                    showStatusMessage('Thank you! Your report has been submitted for review.', 'success');
                } else {
                    showStatusMessage('Report logged locally. Please use the extension popup to submit online reports.', 'info');
                }
            });
        } catch (error) {
            setButtonLoading('report-btn', false);
            console.error('Error reporting site:', error);
            showStatusMessage('Error submitting report. Please use the extension popup.', 'error');
        }
    } else {
        setButtonLoading('report-btn', false);

        // Fallback: log report locally
        const reportData = {
            url: blockedUrl,
            reason_flagged: blockedreason_flagged,
            reportedAt: new Date().toISOString(),
            type: 'false_positive'
        };

        console.log('False positive report (logged locally):', reportData);
        showStatusMessage('Report logged. Please use the extension popup to submit online reports.', 'info');
    }
}

// Initialize page function from the original HTML script
function initializePage() {
    // Get URL parameters
    blockedUrl = getUrlParameter('url') || '';
    blockedreason_flagged = getUrlParameter('reason_flagged') || 'Website flagged as potentially dangerous';

    // Update display elements
    const urlElement = document.getElementById('blocked-url');
    const reason_flaggedElement = document.getElementById('blocked-reason_flagged');

    if (urlElement) {
        urlElement.textContent = blockedUrl || 'Unknown URL';
    }

    if (reason_flaggedElement) {
        reason_flaggedElement.textContent = blockedreason_flagged;
    }

    // Add event listeners to buttons
    const goBackBtn = document.getElementById('go-back-btn');
    const whitelistBtn = document.getElementById('whitelist-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const reportBtn = document.getElementById('report-btn');

    if (goBackBtn) {
        goBackBtn.addEventListener('click', handleGoBack);
    }

    if (whitelistBtn) {
        whitelistBtn.addEventListener('click', handleAddToWhitelist);
    }

    if (settingsBtn) {
        settingsBtn.addEventListener('click', handleOpenSettings);
    }

    if (reportBtn) {
        reportBtn.addEventListener('click', handleReportSite);
    }

    console.log('FountainScan blocked page initialized:', {
        url: blockedUrl,
        reason_flagged: blockedreason_flagged,
        extensionDetected: isExtensionContext()
    });
}

// Handle messages from background script from the original HTML script
if (isExtensionContext()) {
    chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
        console.log('Received message:', message);

        switch (message.action) {
            case 'whitelistAdded':
                showStatusMessage('Site whitelisted! Redirecting...', 'success');
                if (blockedUrl) {
                    setTimeout(() => {
                        window.location.href = blockedUrl;
                    }, 1500);
                }
                sendResponse({success: true});
                break;

            case 'reportReceived':
                showStatusMessage('Report received successfully!', 'success');
                sendResponse({success: true});
                break;

            default:
                sendResponse({success: false, error: 'Unknown action'});
        }
    });
}

// Original BlockedPage object (preserved as requested)
const BlockedPage = {
  currentUrl: '',
  reasonFlagged: '',
  riskLevel: '',

  // Initialize blocked page
  async init() {
    await this.loadBlockInfo();
    this.renderBlockMessage();
    this.setupEventListeners();
  },

  // Load block info from chrome.runtime or query params
  async loadBlockInfo() {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      try {
        const response = await new Promise(resolve => {
          chrome.runtime.sendMessage({ action: 'getBlockInfo' }, resolve);
        });
        if (response) {
          this.currentUrl = response.url || '';
          this.reasonFlagged = response.reason_flagged || '';
          this.riskLevel = response.riskLevel || 'High Risk';
        }
      } catch (e) {
        this.loadFromQueryParams();
      }
    } else {
      this.loadFromQueryParams();
    }
  },

  loadFromQueryParams() {
    const params = new URLSearchParams(window.location.search);
    this.currentUrl = params.get('url') || '';
    this.reasonFlagged = params.get('reason_flagged') || '';
    this.riskLevel = params.get('riskLevel') || 'High Risk';
  },

  renderBlockMessage() {
    const container = document.getElementById('block-container');
    if (!container) return;
    container.innerHTML = `
      <div style="text-align: center; padding: 20px; color: #d32f2f;">
        <h2>🚫 Website Blocked</h2>
        <p><strong>URL:</strong> ${this.currentUrl}</p>
        <p><strong>Risk Level:</strong> ${this.riskLevel}</p>
        <p><strong>Reason:</strong> ${this.reasonFlagged}</p>
        <div style="margin-top: 20px;">
          <button id="addWhitelistBtn" style="margin: 5px; padding: 8px 16px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer;">Add to Whitelist</button>
          <button id="disableBlockingBtn" style="margin: 5px; padding: 8px 16px; background: #ff9800; color: white; border: none; border-radius: 4px; cursor: pointer;">Disable Blocking</button>
          <button id="closeTabBtn" style="margin: 5px; padding: 8px 16px; background: #f44336; color: white; border: none; border-radius: 4px; cursor: pointer;">Close Tab</button>
        </div>
      </div>
    `;
  },

  setupEventListeners() {
    document.addEventListener('click', async (e) => {
      if (e.target.id === 'addWhitelistBtn') {
        await this.addCurrentToWhitelist();
      } else if (e.target.id === 'disableBlockingBtn') {
        await this.disableBlocking();
      } else if (e.target.id === 'closeTabBtn') {
        window.close();
      }
    });
  },

  async addCurrentToWhitelist() {
    try {
      const url = new URL(this.currentUrl);
      const domain = url.hostname.toLowerCase().replace(/^www\./, '');
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['whitelist'], (result) => {
          const whitelist = result.whitelist || [];
          if (!whitelist.some(d => d.toLowerCase() === domain)) {
            whitelist.push(domain);
            chrome.storage.local.set({ whitelist }, () => {
              if (typeof chrome !== 'undefined' && chrome.tabs) {
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                  if (tabs[0]) {
                    chrome.tabs.reload(tabs[0].id);
                    window.close();
                  }
                });
              }
            });
          }
        });
      }
    } catch (error) {
      console.error('Error adding to whitelist:', error);
    }
  },

  async disableBlocking() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['settings'], (result) => {
        const settings = result.settings || {};
        settings.blockingEnabled = false;
        chrome.storage.local.set({ settings }, () => {
          if (typeof chrome !== 'undefined' && chrome.tabs) {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
              if (tabs[0]) {
                chrome.tabs.reload(tabs[0].id);
                window.close();
              }
            });
          }
        });
      });
    }
  }
};

// Make BlockedPage available globally
window.BlockedPage = BlockedPage;

// Initialize when DOM is ready (from the original HTML script)
document.addEventListener('DOMContentLoaded', () => {
  // Initialize the new functionality first
  initializePage();
  // Then initialize the original BlockedPage (if needed)
  // BlockedPage.init();
});

// Fallback initialization if DOMContentLoaded already fired (from the original HTML script)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initializePage();
        // BlockedPage.init();
    });
} else {
    initializePage();
    // BlockedPage.init();
}