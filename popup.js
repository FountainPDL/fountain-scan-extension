//popup.js
// Extension state management
const FountainScan = {
  currentUrl: '',
  settings: {
    theme: 'light',
    alertsEnabled: true,
    blockingEnabled: false,
    systemLang: 'en-NG',
    alertLang: 'en'
  },
  whitelist: [],
  blacklist: [],
  
  // Initialize extension
  init() {
    this.loadSettings();
    this.loadLists();
    this.setupEventListeners();
    this.switchTab('home');
    this.scanCurrentSite();
    // Initialize blocking system
    this.initializeBlocking();
  },

  // Initialize blocking system
  initializeBlocking() {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      // Send current settings to background script
      chrome.runtime.sendMessage({
        action: 'updateSettings',
        settings: this.settings,
        blacklist: this.blacklist,
        whitelist: this.whitelist
      });
    }
  },

  // Load settings from storage
  loadSettings() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['settings'], (result) => {
          if (result.settings) {
            this.settings = { ...this.settings, ...result.settings };
            this.applySettings();
            // Update blocking when settings load
            this.updateBlockingRules();
          }
        });
      } else {
        // Fallback for testing without chrome extension API
        const saved = localStorage.getItem('fountainScanSettings');
        if (saved) {
          this.settings = { ...this.settings, ...JSON.parse(saved) };
          this.applySettings();
        }
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  },

  // Save settings to storage
  saveSettings() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ settings: this.settings });
      } else {
        localStorage.setItem('fountainScanSettings', JSON.stringify(this.settings));
      }
      // Update blocking rules when settings change
      this.updateBlockingRules();
      this.showMessage('Settings saved successfully!', 'success');
    } catch (error) {
      console.error('Error saving settings:', error);
      this.showMessage('Error saving settings', 'error');
    }
  },

  // Load whitelist/blacklist from storage
  loadLists() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['whitelist', 'blacklist'], (result) => {
          this.whitelist = result.whitelist || [];
          this.blacklist = result.blacklist || [];
          this.renderLists();
          // Update blocking rules when lists load
          this.updateBlockingRules();
        });
      } else {
        // Fallback for testing
        this.whitelist = JSON.parse(localStorage.getItem('fountainScanWhitelist') || '[]');
        this.blacklist = JSON.parse(localStorage.getItem('fountainScanBlacklist') || '[]');
        this.renderLists();
      }
    } catch (error) {
      console.error('Error loading lists:', error);
    }
  },

  // Save lists to storage
  saveLists() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ 
          whitelist: this.whitelist, 
          blacklist: this.blacklist 
        });
      } else {
        localStorage.setItem('fountainScanWhitelist', JSON.stringify(this.whitelist));
        localStorage.setItem('fountainScanBlacklist', JSON.stringify(this.blacklist));
      }
      // Update blocking rules when lists change
      this.updateBlockingRules();
    } catch (error) {
      console.error('Error saving lists:', error);
    }
  },

  // Update blocking rules in background script
  updateBlockingRules() {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        action: 'updateBlockingRules',
        settings: this.settings,
        blacklist: this.blacklist,
        whitelist: this.whitelist
      }).catch(error => {
        console.log('Background script not ready:', error);
      });
    }
  },

  // Setup event listeners
  setupEventListeners() {
    // Navigation buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetTab = e.target.dataset.tab;
        this.switchTab(targetTab);
      });
    });

    // Action buttons
    const rescanBtn = document.getElementById('rescanBtn');
    const addWhitelistBtn = document.getElementById('addWhitelistBtn');
    const addBlacklistBtn = document.getElementById('addBlacklistBtn');
    const reportBtn = document.getElementById('reportBtn');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');

    if (rescanBtn) {
      rescanBtn.addEventListener('click', () => this.rescanSite());
    }
    if (addWhitelistBtn) {
      addWhitelistBtn.addEventListener('click', () => this.addToList('whitelist'));
    }
    if (addBlacklistBtn) {
      addBlacklistBtn.addEventListener('click', () => this.addToList('blacklist'));
    }
    if (reportBtn) {
      reportBtn.addEventListener('click', () => this.reportSite());
    }
    if (saveSettingsBtn) {
      saveSettingsBtn.addEventListener('click', () => this.saveSettingsFromForm());
    }

    // Enter key support for input fields
    const whitelistInput = document.getElementById('whitelistInput');
    const blacklistInput = document.getElementById('blacklistInput');
    if (whitelistInput) {
      whitelistInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          this.addToList('whitelist');
        }
      });
    }
    if (blacklistInput) {
      blacklistInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          this.addToList('blacklist');
        }
      });
    }

    // Theme change listeners
    document.querySelectorAll("input[name='theme']").forEach(radio => {
      radio.addEventListener("change", (e) => {
        this.settings.theme = e.target.value;
        this.applyTheme(e.target.value);
      });
    });

    // Settings change listeners
    const alertToggle = document.getElementById('alertToggle');
    const blockToggle = document.getElementById('blockToggle');
    if (alertToggle) {
      alertToggle.addEventListener('change', (e) => {
        this.settings.alertsEnabled = e.target.checked;
      });
    }
    if (blockToggle) {
      blockToggle.addEventListener('change', (e) => {
        this.settings.blockingEnabled = e.target.checked;
        // Update blocking immediately when toggle changes
        this.updateBlockingRules();
      });
    }

    // Input validation
    document.querySelectorAll('input[type="text"], input[type="url"]').forEach(input => {
      input.addEventListener('input', this.validateInput.bind(this));
    });

    // Listen for messages from blocked page
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        this.handleMessage(message, sender, sendResponse);
        return true; // Keep message channel open
      });
    }
  },

  // Handle messages from blocked page and background script
  handleMessage(message, sender, sendResponse) {
    switch (message.action) {
      case 'addToWhitelist':
        this.handleWhitelistRequest(message, sendResponse);
        break;
      case 'reportFalsePositive':
        this.handleReportRequest(message, sendResponse);
        break;
      case 'getBlockInfo':
        this.handleBlockInfoRequest(sendResponse);
        break;
      default:
        sendResponse({ success: false, error: 'Unknown action' });
    }
  },

  // Handle whitelist request from blocked page
  async handleWhitelistRequest(message, sendResponse) {
    try {
      const domain = message.domain;
      if (!domain) {
        sendResponse({ success: false, error: 'No domain provided' });
        return;
      }

      // Validate domain
      if (!this.isValidDomain(domain)) {
        sendResponse({ success: false, error: 'Invalid domain format' });
        return;
      }

      // Add to whitelist if not already present
      if (!this.whitelist.some(d => d.toLowerCase() === domain.toLowerCase())) {
        this.whitelist.push(domain);
        this.saveLists();
        this.renderLists();
        
        // Notify background script to unblock
        chrome.runtime.sendMessage({
          action: 'unblockDomain',
          domain: domain
        });

        sendResponse({ success: true, message: 'Domain added to whitelist' });
      } else {
        sendResponse({ success: false, error: 'Domain already in whitelist' });
      }
    } catch (error) {
      console.error('Error handling whitelist request:', error);
      sendResponse({ success: false, error: error.message });
    }
  },

  // Handle report request from blocked page
  async handleReportRequest(message, sendResponse) {
    try {
      const { url, reason_flagged, timestamp } = message;
      
      // Submit report to backend
      const response = await fetch('https://backend-uwk4.onrender.com/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url,
          reason_flagged: reason_flagged || 'Reported as false positive',
          email: null,
          timestamp: timestamp || new Date().toISOString(),
          type: 'false_positive'
        })
      });
      
      const result = await response.json();
      
      if (response.ok && result.success) {
        sendResponse({ success: true, message: 'Report submitted successfully' });
      } else {
        throw new Error(result.error || 'Failed to submit report');
      }
      
    } catch (error) {
      console.error('Error submitting report:', error);
      
      // Log locally as fallback
      console.log('Report (logged locally):', {
        url: message.url,
        reason_flagged: message.reason_flagged,
        timestamp: message.timestamp || new Date().toISOString(),
        type: 'false_positive',
        error: error.message
      });
      
      sendResponse({ 
        success: false, 
        error: 'Report logged locally due to network error',
        logged: true 
      });
    }
  },

  // Handle block info request from blocked page
  handleBlockInfoRequest(sendResponse) {
    // Get the most recent block info from storage or current state
    chrome.storage.local.get(['lastBlockedSite'], (result) => {
      const blockInfo = result.lastBlockedSite || {
        url: this.currentUrl || '',
        reason_flagged: 'Website flagged as potentially dangerous',
        riskLevel: 'High Risk',
        timestamp: new Date().toISOString()
      };
      sendResponse(blockInfo);
    });
  },

  // Enhanced domain matching for whitelist/blacklist
  domainMatches(currentDomain, listDomain) {
    // Remove protocol and www if present
    const cleanDomain = listDomain.replace(/^(https?:\/\/)?(www\.)?/, '').toLowerCase();
    const cleanCurrent = currentDomain.replace(/^(www\.)?/, '').toLowerCase();
    
    // Exact match
    if (cleanCurrent === cleanDomain) return true;
    
    // Subdomain match (e.g., sub.example.com matches example.com)
    if (cleanCurrent.endsWith('.' + cleanDomain)) return true;
    
    // Wildcard support (e.g., *.example.com)
    if (cleanDomain.startsWith('*.')) {
      const baseDomain = cleanDomain.substring(2);
      return cleanCurrent.endsWith('.' + baseDomain) || cleanCurrent === baseDomain;
    }
    
    return false;
  },

  // Validate base domain format
  isValidBaseDomain(domain) {
    // Basic domain regex with support for international domains
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
    
    // Check basic format
    if (!domainRegex.test(domain)) return false;
    
    // Additional checks
    if (domain.length > 253) return false; // Max domain length
    if (domain.includes('..')) return false; // No consecutive dots
    if (domain.startsWith('-') || domain.endsWith('-')) return false; // No leading/trailing hyphens
    
    return true;
  },

  // Enhanced domain validation
  isValidDomain(domain) {
    // Clean the domain
    const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').toLowerCase();
    
    // Check for wildcard pattern
    if (cleanDomain.startsWith('*.')) {
      const baseDomain = cleanDomain.substring(2);
      return this.isValidBaseDomain(baseDomain);
    }
    
    return this.isValidBaseDomain(cleanDomain);
  },

  // Normalize domain input
  normalizeDomain(input) {
    if (!input) return '';
    
    // Remove protocol, www, and trailing slash
    let domain = input.toLowerCase()
      .replace(/^(https?:\/\/)?(www\.)?/, '')
      .replace(/\/$/, '');
    
    // Remove path, query, and fragment
    domain = domain.split('/')[0].split('?')[0].split('#')[0];
    
    // Remove port if present
    domain = domain.split(':')[0];
    
    return domain.trim();
  },

  // Enhanced input validation with real-time feedback
  validateInput(event) {
    const input = event.target;
    const value = input.value.trim();
    const errorElement = input.parentElement.querySelector('.input-error');
    
    // Remove existing error message
    if (errorElement) {
      errorElement.remove();
    }
    
    let isValid = true;
    let errorMessage = '';
    
    if (value) {
      if (input.type === 'url') {
        if (!this.isValidUrl(value)) {
          isValid = false;
          errorMessage = 'Please enter a valid URL (e.g., https://example.com)';
        }
      } else if (input.id.includes('Input')) {
        const normalizedDomain = this.normalizeDomain(value);
        if (!this.isValidDomain(normalizedDomain)) {
          isValid = false;
          errorMessage = 'Please enter a valid domain (e.g., example.com or *.example.com)';
        }
      }
    }
    
    // Update input styling and validation
    if (isValid) {
      input.setCustomValidity('');
      input.classList.remove('invalid');
      input.classList.add('valid');
    } else {
      input.setCustomValidity(errorMessage);
      input.classList.remove('valid');
      input.classList.add('invalid');
      
      // Show error message
      const errorDiv = document.createElement('div');
      errorDiv.className = 'input-error';
      errorDiv.textContent = errorMessage;
      input.parentElement.appendChild(errorDiv);
    }
  },

  // Validate URL format
  isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  },

  // Apply theme and settings
  applySettings() {
    this.applyTheme(this.settings.theme);
    
    // Update UI elements
    const alertToggle = document.getElementById('alertToggle');
    const blockToggle = document.getElementById('blockToggle');
    const systemLang = document.getElementById('systemLang');
    const alertLang = document.getElementById('alertLang');
    
    if (alertToggle) alertToggle.checked = this.settings.alertsEnabled;
    if (blockToggle) blockToggle.checked = this.settings.blockingEnabled;
    if (systemLang) systemLang.value = this.settings.systemLang;
    if (alertLang) alertLang.value = this.settings.alertLang;
    
    // Update theme radio buttons
    const themeRadio = document.querySelector(`input[name="theme"][value="${this.settings.theme}"]`);
    if (themeRadio) themeRadio.checked = true;
  },

  // Apply theme
  applyTheme(theme) {
    document.body.className = theme;
    this.settings.theme = theme;
  },

  // Switch between tabs
  switchTab(targetId) {
    // Remove active class from all tabs and nav buttons
    document.querySelectorAll(".tab").forEach(tab => {
      tab.classList.remove("active");
    });
    document.querySelectorAll(".nav-btn").forEach(btn => {
      btn.classList.remove("active");
    });
    
    // Add active class to target tab and nav button
    const targetTab = document.getElementById(targetId);
    const targetBtn = document.querySelector(`[data-tab="${targetId}"]`);
    
    if (targetTab) {
      targetTab.classList.add("active");
    }
    if (targetBtn) {
      targetBtn.classList.add("active");
    }
  },

  // Get current tab URL
  getCurrentUrl() {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          resolve(tabs[0]?.url || 'about:blank');
        });
      } else {
        // Fallback for testing
        resolve(window.location.href);
      }
    });
  },

  // Main scan function - unified and organized
  async scanCurrentSite() {
    try {
      const url = await this.getCurrentUrl();
      this.currentUrl = url;
      
      // Update UI elements
      const urlElement = document.getElementById('url');
      const statusElement = document.getElementById('status');
      const reason_flaggedElement = document.getElementById('reason_flagged');
      const statusCircle = document.getElementById('status-circle');
      const statusText = document.getElementById('status-text');
      
      if (urlElement) urlElement.textContent = url;
      
      // Set initial analyzing state
      if (statusText) statusText.textContent = 'Analyzing...';
      if (statusCircle) statusCircle.style.background = 'gray';
      
      // Perform comprehensive scan
      const scanResult = await this.performComprehensiveScan(url);
      
      // Update status elements
      if (statusElement) {
        statusElement.textContent = scanResult.status;
        statusElement.className = `status-${scanResult.level}`;
      }
      
      if (reason_flaggedElement) {
        reason_flaggedElement.textContent = scanResult.issues.length > 0 ? 
          scanResult.issues.join(', ') : 'No issues detected';
      }
      
      // Update status circle and text
      this.updateStatusUI(scanResult, statusCircle, statusText);
      
      // Handle blocking for dangerous sites
      if (scanResult.level === 'danger' && this.settings.blockingEnabled) {
        // Check if site should be blocked
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase();
        
        // Don't block if whitelisted
        if (!this.whitelist.some(d => this.domainMatches(domain, d.toLowerCase()))) {
          // Store block info for blocked page
          await this.storeBlockInfo({
            url: url,
            reason_flagged: scanResult.issues.join(', '),
            riskLevel: scanResult.status,
            timestamp: new Date().toISOString()
          });
          
          this.handleDangerousSite(scanResult);
          return; // Exit early if blocking
        }
      }
      
      // Show alert if needed (for non-blocked dangerous sites)
      if (scanResult.level === 'danger' && this.settings.alertsEnabled) {
        this.showAlert(scanResult);
      }
      
    } catch (error) {
      console.error('Error scanning site:', error);
      this.showMessage('Error scanning current site', 'error');
      
      // Update UI to show error state
      const statusText = document.getElementById('status-text');
      const statusCircle = document.getElementById('status-circle');
      if (statusText) statusText.textContent = 'Error';
      if (statusCircle) statusCircle.style.background = 'gray';
    }
  },

  // Store block info for blocked page access
  async storeBlockInfo(blockInfo) {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ lastBlockedSite: blockInfo });
    }
  },

  // Handle dangerous sites with blocking option
  async handleDangerousSite(scanResult) {
    if (this.settings.blockingEnabled) {
      // Immediately notify background script to block
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        chrome.runtime.sendMessage({
          action: 'blo