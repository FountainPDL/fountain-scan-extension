// blocked.js - Handles blocked.html UI and actions for FountainScan

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

window.BlockedPage = BlockedPage;
document.addEventListener('DOMContentLoaded', () => {
  BlockedPage.init();
});
