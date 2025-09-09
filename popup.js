//popup.js - Extension state management
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

  init() { // Initialize extension
    this.loadSettings();
    this.loadLists();
    this.setupEventListeners();
    this.switchTab('home');
    this.scanCurrentSite();
    this.initializeBlocking(); // Initialize blocking system
  },

  initializeBlocking() { // Initialize blocking system
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ // Send current settings to background script
        action: 'updateSettings',
        settings: this.settings,
        blacklist: this.blacklist,
        whitelist: this.whitelist
      });
    }
  },

  loadSettings() { // Load settings from storage
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['settings'], (result) => {
          if (result.settings) {
            this.settings = { ...this.settings, ...result.settings };
            this.applySettings();
            this.updateBlockingRules(); // Update blocking when settings load
          }
        });
      } else {
        const saved = localStorage.getItem('fountainScanSettings'); // Fallback for testing without chrome extension API
        if (saved) {
          this.settings = { ...this.settings, ...JSON.parse(saved) };
          this.applySettings();
        }
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  },

  saveSettings() { // Save settings to storage
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ settings: this.settings });
      } else {
        localStorage.setItem('fountainScanSettings', JSON.stringify(this.settings));
      }
      this.updateBlockingRules(); // Update blocking rules when settings change
      this.showMessage('Settings saved successfully!', 'success');
    } catch (error) {
      console.error('Error saving settings:', error);
      this.showMessage('Error saving settings', 'error');
    }
  },

  loadLists() { // Load whitelist/blacklist from storage
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['whitelist', 'blacklist'], (result) => {
          this.whitelist = result.whitelist || [];
          this.blacklist = result.blacklist || [];
          this.renderLists();
          this.updateBlockingRules(); // Update blocking rules when lists load
        });
      } else {
        this.whitelist = JSON.parse(localStorage.getItem('fountainScanWhitelist') || '[]'); // Fallback for testing
        this.blacklist = JSON.parse(localStorage.getItem('fountainScanBlacklist') || '[]');
        this.renderLists();
      }
    } catch (error) {
      console.error('Error loading lists:', error);
    }
  },

  saveLists() { // Save lists to storage
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
      this.updateBlockingRules(); // Update blocking rules when lists change
    } catch (error) {
      console.error('Error saving lists:', error);
    }
  },

  updateBlockingRules() { // Update blocking rules in background script
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

  setupEventListeners() { // Setup event listeners
    document.querySelectorAll('.nav-btn').forEach(btn => { // Navigation buttons
      btn.addEventListener('click', (e) => {
        const targetTab = e.target.dataset.tab;
        this.switchTab(targetTab);
      });
    });

    const rescanBtn = document.getElementById('rescanBtn'); // Action buttons
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

    const whitelistInput = document.getElementById('whitelistInput'); // Enter key support for input fields
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

    document.querySelectorAll("input[name='theme']").forEach(radio => { // Theme change listeners
      radio.addEventListener("change", (e) => {
        this.settings.theme = e.target.value;
        this.applyTheme(e.target.value);
      });
    });

    const alertToggle = document.getElementById('alertToggle'); // Settings change listeners
    const blockToggle = document.getElementById('blockToggle');
    if (alertToggle) {
      alertToggle.addEventListener('change', (e) => {
        this.settings.alertsEnabled = e.target.checked;
      });
    }
    if (blockToggle) {
      blockToggle.addEventListener('change', (e) => {
        this.settings.blockingEnabled = e.target.checked;
        this.updateBlockingRules(); // Update blocking immediately when toggle changes
      });
    }

    document.querySelectorAll('input[type="text"], input[type="url"]').forEach(input => { // Input validation
      input.addEventListener('input', this.validateInput.bind(this));
    });

    if (typeof chrome !== 'undefined' && chrome.runtime) { // Listen for messages from blocked page
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        this.handleMessage(message, sender, sendResponse);
        return true; // Keep message channel open
      });
    }
  },

  handleMessage(message, sender, sendResponse) { // Handle messages from blocked page and background script
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

  async handleWhitelistRequest(message, sendResponse) { // Handle whitelist request from blocked page
    try {
      const domain = message.domain;
      if (!domain) {
        sendResponse({ success: false, error: 'No domain provided' });
        return;
      }

      if (!this.isValidDomain(domain)) { // Validate domain
        sendResponse({ success: false, error: 'Invalid domain format' });
        return;
      }

      if (!this.whitelist.some(d => d.toLowerCase() === domain.toLowerCase())) { // Add to whitelist if not already present
        this.whitelist.push(domain);
        this.saveLists();
        this.renderLists();

        chrome.runtime.sendMessage({ // Notify background script to unblock
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

  async handleReportRequest(message, sendResponse) { // Handle report request from blocked page
    try {
      const { url, reason_flagged, timestamp } = message;

      const response = await fetch('https://backend-uwk4.onrender.com/report', { // Submit report to backend
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

      console.log('Report (logged locally):', { // Log locally as fallback
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

  handleBlockInfoRequest(sendResponse) { // Handle block info request from blocked page
    chrome.storage.local.get(['lastBlockedSite'], (result) => { // Get the most recent block info from storage or current state
      const blockInfo = result.lastBlockedSite || {
        url: this.currentUrl || '',
        reason_flagged: 'Website flagged as potentially dangerous',
        riskLevel: 'High Risk',
        timestamp: new Date().toISOString()
      };
      sendResponse(blockInfo);
    });
  },

  domainMatches(currentDomain, listDomain) { // Enhanced domain matching for whitelist/blacklist
    const cleanDomain = listDomain.replace(/^(https?:\/\/)?(www\.)?/, '').toLowerCase(); // Remove protocol and www if present
    const cleanCurrent = currentDomain.replace(/^(www\.)?/, '').toLowerCase();

    if (cleanCurrent === cleanDomain) return true; // Exact match
    if (cleanCurrent.endsWith('.' + cleanDomain)) return true; // Subdomain match (e.g., sub.example.com matches example.com)
    
    if (cleanDomain.startsWith('*.')) { // Wildcard support (e.g., *.example.com)
      const baseDomain = cleanDomain.substring(2);
      return cleanCurrent.endsWith('.' + baseDomain) || cleanCurrent === baseDomain;
    }

    return false;
  },

  isValidBaseDomain(domain) { // Validate base domain format
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/; // Basic domain regex with support for international domains

    if (!domainRegex.test(domain)) return false; // Check basic format
    if (domain.length > 253) return false; // Additional checks - Max domain length
    if (domain.includes('..')) return false; // No consecutive dots
    if (domain.startsWith('-') || domain.endsWith('-')) return false; // No leading/trailing hyphens

    return true;
  },

  isValidDomain(domain) { // Enhanced domain validation
    const cleanDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').toLowerCase(); // Clean the domain

    if (cleanDomain.startsWith('*.')) { // Check for wildcard pattern
      const baseDomain = cleanDomain.substring(2);
      return this.isValidBaseDomain(baseDomain);
    }

    return this.isValidBaseDomain(cleanDomain);
  },

  normalizeDomain(input) { // Normalize domain input
    if (!input) return '';

    let domain = input.toLowerCase() // Remove protocol, www, and trailing slash
      .replace(/^(https?:\/\/)?(www\.)?/, '')
      .replace(/\/$/, '');

    domain = domain.split('/')[0].split('?')[0].split('#')[0]; // Remove path, query, and fragment
    domain = domain.split(':')[0]; // Remove port if present

    return domain.trim();
  },

  validateInput(event) { // Enhanced input validation with real-time feedback
    const input = event.target;
    const value = input.value.trim();
    const errorElement = input.parentElement.querySelector('.input-error');

    if (errorElement) { // Remove existing error message
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

    if (isValid) { // Update input styling and validation
      input.setCustomValidity('');
      input.classList.remove('invalid');
      input.classList.add('valid');
    } else {
      input.setCustomValidity(errorMessage);
      input.classList.remove('valid');
      input.classList.add('invalid');

      const errorDiv = document.createElement('div'); // Show error message
      errorDiv.className = 'input-error';
      errorDiv.textContent = errorMessage;
      input.parentElement.appendChild(errorDiv);
    }
  },

  isValidUrl(string) { // Validate URL format
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  },

  applySettings() { // Apply theme and settings
    this.applyTheme(this.settings.theme);

    const alertToggle = document.getElementById('alertToggle'); // Update UI elements
    const blockToggle = document.getElementById('blockToggle');
    const systemLang = document.getElementById('systemLang');
    const alertLang = document.getElementById('alertLang');

    if (alertToggle) alertToggle.checked = this.settings.alertsEnabled;
    if (blockToggle) blockToggle.checked = this.settings.blockingEnabled;
    if (systemLang) systemLang.value = this.settings.systemLang;
    if (alertLang) alertLang.value = this.settings.alertLang;

    const themeRadio = document.querySelector(`input[name="theme"][value="${this.settings.theme}"]`); // Update theme radio buttons
    if (themeRadio) themeRadio.checked = true;
  },

  applyTheme(theme) { // Apply theme
    document.body.className = theme;
    this.settings.theme = theme;
  },

  switchTab(targetId) { // Switch between tabs
    document.querySelectorAll(".tab").forEach(tab => { // Remove active class from all tabs and nav buttons
      tab.classList.remove("active");
    });
    document.querySelectorAll(".nav-btn").forEach(btn => {
      btn.classList.remove("active");
    });

    const targetTab = document.getElementById(targetId); // Add active class to target tab and nav button
    const targetBtn = document.querySelector(`[data-tab="${targetId}"]`);

    if (targetTab) {
      targetTab.classList.add("active");
    }
    if (targetBtn) {
      targetBtn.classList.add("active");
    }
  },

  getCurrentUrl() { // Get current tab URL
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          resolve(tabs[0]?.url || 'about:blank');
        });
      } else {
        resolve(window.location.href); // Fallback for testing
      }
    });
  },

  async fetchSupabaseBlacklist() { // Fetch blacklist from Supabase database
    try {
      const response = await fetch('https://backend-uwk4.onrender.com/blacklist', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        }
      });

      if (response.ok) {
        const result = await response.json();
        return result.blacklist || [];
      } else {
        console.error('Failed to fetch Supabase blacklist:', response.status);
        return [];
      }
    } catch (error) {
      console.error('Error fetching Supabase blacklist:', error);
      return [];
    }
  },

  animateStatusCircle(element, status) { // Add animation to status circle
    if (!element) return;

    element.style.transition = 'all 0.3s ease-in-out'; // Remove existing animations
    element.classList.remove('pulse-animation', 'danger-pulse', 'warning-pulse', 'safe-pulse');

    let backgroundColor, animation;
    
    switch (status) {
      case 'danger':
        backgroundColor = '#e74c3c';
        animation = 'danger-pulse';
        break;
      case 'warning':
        backgroundColor = '#f39c12';
        animation = 'warning-pulse';
        break;
      case 'safe':
        backgroundColor = '#27ae60';
        animation = 'safe-pulse';
        break;
      default:
        backgroundColor = '#6c757d';
        animation = 'pulse-animation';
    }

    element.style.background = backgroundColor;
    
    setTimeout(() => { // Add animation class after a brief delay
      element.classList.add('pulse-animation', animation);
    }, 100);
  },

  async scanCurrentSite() { // Main scan function - unified and organized
    try {
      const url = await this.getCurrentUrl();
      this.currentUrl = url;

      const urlElement = document.getElementById('url'); // Update UI elements
      const statusElement = document.getElementById('status');
      const reason_flaggedElement = document.getElementById('reason_flagged');
      const statusCircle = document.getElementById('status-circle');
      const statusText = document.getElementById('status-text');

      if (urlElement) urlElement.textContent = url;

      if (statusText) statusText.textContent = 'Analyzing...'; // Set initial analyzing state
      if (statusCircle) {
        statusCircle.style.background = 'gray';
        this.animateStatusCircle(statusCircle, 'analyzing');
      }

      const scanResult = await this.performComprehensiveScan(url); // Perform comprehensive scan

      if (statusElement) { // Update status elements
        statusElement.textContent = scanResult.status;
        statusElement.className = `status-${scanResult.level}`;
      }

      if (reason_flaggedElement) {
        reason_flaggedElement.textContent = scanResult.issues.length > 0 ? 
          scanResult.issues.join(', ') : 'No issues detected';
      }

      this.updateStatusUI(scanResult, statusCircle, statusText); // Update status circle and text

      if (scanResult.level === 'danger' && this.settings.blockingEnabled) { // Handle blocking for dangerous sites
        const urlObj = new URL(url); // Check if site should be blocked
        const domain = urlObj.hostname.toLowerCase();

        if (!this.whitelist.some(d => this.domainMatches(domain, d.toLowerCase()))) { // Don't block if whitelisted
          await this.storeBlockInfo({ // Store block info for blocked page
            url: url,
            reason_flagged: scanResult.issues.join(', '),
            riskLevel: scanResult.status,
            score: scanResult.score,
            timestamp: new Date().toISOString()
          });

          this.handleDangerousSite(scanResult);
          return; // Exit early if blocking
        }
