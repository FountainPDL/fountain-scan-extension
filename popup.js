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

    element.style.transition = 'all 0.3s ease-in-out'; // Remove existing animations and apply transition
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
      }
      
      if (scanResult.level === 'danger' && this.settings.alertsEnabled) { // Show alert if needed (for non-blocked dangerous sites)
        this.showAlert(scanResult);
      }
      
    } catch (error) {
      console.error('Error scanning site:', error);
      this.showMessage('Error scanning current site', 'error');
      
      const statusText = document.getElementById('status-text'); // Update UI to show error state
      const statusCircle = document.getElementById('status-circle');
      if (statusText) statusText.textContent = 'Error';
      if (statusCircle) {
        statusCircle.style.background = 'gray';
        this.animateStatusCircle(statusCircle, 'error');
      }
    }
  },

  async storeBlockInfo(blockInfo) { // Store block info for blocked page access
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ lastBlockedSite: blockInfo });
    }
  },

  async handleDangerousSite(scanResult) { // Handle dangerous sites with blocking option
    if (this.settings.blockingEnabled) {
      if (typeof chrome !== 'undefined' && chrome.runtime) { // Immediately notify background script to block
        chrome.runtime.sendMessage({
          action: 'blockCurrentTab',
          url: this.currentUrl,
          reason_flagged: `${scanResult.issues.join(', ')} - Score: ${scanResult.score}`
        });
      }
      
      this.showBlockingMessage(scanResult); // Show blocking message in popup
    } else {
      this.showAlert(scanResult); // Just show alert if blocking is disabled
    }
  },

  showBlockingMessage(scanResult) { // Show blocking message
    const activeTab = document.querySelector('.tab.active'); // Replace popup content with blocking message
    if (activeTab) {
      activeTab.innerHTML = `
        <div style="text-align: center; padding: 20px; color: #d32f2f;">
          <h2>🚫 Website Blocked</h2>
          <p><strong>URL:</strong> ${this.currentUrl}</p>
          <p><strong>Risk Level:</strong> ${scanResult.status}</p>
          <p><strong>Score:</strong> ${scanResult.score}/100</p>
          <p><strong>Reasons:</strong> ${scanResult.issues.join(', ')}</p>
          <div style="margin-top: 20px;">
            <button onclick="FountainScan.addCurrentToWhitelist()" style="margin: 5px; padding: 8px 16px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer;">Add to Whitelist</button>
            <button onclick="FountainScan.disableBlocking()" style="margin: 5px; padding: 8px 16px; background: #ff9800; color: white; border: none; border-radius: 4px; cursor: pointer;">Disable Blocking</button>
            <button onclick="window.close()" style="margin: 5px; padding: 8px 16px; background: #f44336; color: white; border: none; border-radius: 4px; cursor: pointer;">Close Tab</button>
          </div>
        </div>
      `;
    }
  },

  async addCurrentToWhitelist() { // Add current site to whitelist from blocking screen
    try {
      const url = new URL(this.currentUrl);
      const domain = url.hostname.toLowerCase().replace(/^www\./, '');
      
      if (!this.whitelist.some(d => d.toLowerCase() === domain)) {
        this.whitelist.push(domain);
        this.saveLists();
        
        if (typeof chrome !== 'undefined' && chrome.tabs) { // Reload the tab to unblock
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab) {
            chrome.tabs.reload(tab.id);
            window.close(); // Close popup
          }
        }
      }
    } catch (error) {
      console.error('Error adding to whitelist:', error);
    }
  },

  disableBlocking() { // Disable blocking from blocking screen
    this.settings.blockingEnabled = false;
    this.saveSettings();
    
    if (typeof chrome !== 'undefined' && chrome.tabs) { // Reload the tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.reload(tabs[0].id);
          window.close(); // Close popup
        }
      });
    }
  },

  updateStatusUI(scanResult, statusCircle, statusText) { // Update status UI components with animation and score
    if (!statusCircle || !statusText) return;
    
    if (statusText) {
      statusText.textContent = `${scanResult.status} (Score: ${scanResult.score || 0})`;
    }

    if (statusCircle) {
      this.animateStatusCircle(statusCircle, scanResult.level);
    }
  },

  getDetectionPatterns() { // Enhanced detection patterns
    return {
      scholarshipScams: { // High-risk scholarship scam patterns
        keywords: [
          'free-scholarship', 'guaranteed-scholarship', 'instant-scholarship',
          'scholarship-winner', 'congratulations-scholarship', 'scholarship-alert',
          'urgent-scholarship', 'limited-scholarship', 'scholarship-opportunity',
          'scholarship-grant', 'education-grant', 'student-aid-program',
          'free scholarship', 'instant money', 'guaranteed loan',
          'easy cash', 'work from home', 'get rich quick',
          'no-experience-required', 'make-money-fast', 
          'nin', 'bvn', 'guaranteed', 'National Identity Number', 
          'free', 'Bank Verification Number', 'payment verification', 'pin'
        ],
        score: 4,
        message: 'Potential scholarship scam detected'
      },
      
      financialFraud: { // Financial fraud patterns
        keywords: [
          'instant-money', 'guaranteed-loan', 'easy-cash', 'quick-loan',
          'no-collateral', 'emergency-loan', 'same-day-loan', 'payday-loan',
          'cash-advance', 'loan-approved', 'credit-repair', 'debt-relief'
        ],
        score: 3,
        message: 'Financial fraud pattern detected'
      },
      
      nigerianScams: { // Nigerian-specific scam patterns
        keywords: [
          'npower', 'jamb-result', 'waec-result', 'inec-recruitment',
          'nnpc-recruitment', 'cbn-recruitment', 'federal-government',
          'state-government', 'local-government', 'ministry-recruitment',
          'nddc-scholarship', 'tetfund', 'ptdf-scholarship'
        ],
        score: 3,
        message: 'Nigerian institution impersonation detected'
      },
      
      urgencyTactics: { // Urgency and pressure tactics
        keywords: [
          'urgent', 'limited-time', 'expires-soon', 'act-now',
          'dont-miss-out', 'last-chance', 'hurry', 'immediate',
          'deadline-today', 'offer-expires', 'while-supplies-last'
        ],
        score: 1,
        message: 'Urgency pressure tactic detected'
      }
    };
  },

  async performComprehensiveScan(url) { // Comprehensive scan function combining all checks including Supabase
    const issues = [];
    let score = 0;
    
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      const fullUrl = url.toLowerCase();
      
      if (this.whitelist.some(d => this.domainMatches(domain, d.toLowerCase()))) { // Check if domain is whitelisted (highest priority)
        return {
          status: 'Trusted (Whitelisted)',
          level: 'safe',
          issues: [],
          score: 0
        };
      }
      
      if (this.blacklist.some(d => this.domainMatches(domain, d.toLowerCase()))) { // Check if domain is in local blacklist
        score += 70;
        issues.push('Domain is in local blacklist');
      }

      const supabaseBlacklist = await this.fetchSupabaseBlacklist(); // Check Supabase blacklist
      if (supabaseBlacklist.some(entry => this.domainMatches(domain, entry.domain || entry))) {
        score += 70;
        issues.push('Domain is in security database');
      }
      
      if (urlObj.protocol !== 'https:') { // Security checks
        score += 10;
        issues.push('No HTTPS encryption');
      }
      
      const patterns = this.getDetectionPatterns(); // Enhanced keyword detection
      
      let pageContent = ''; // Get page content if possible
      try {
        if (typeof chrome !== 'undefined' && chrome.tabs && chrome.scripting) {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tab && tab.id) {
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              func: () => document.body.innerText.toLowerCase()
            });
            pageContent = results[0]?.result || '';
          }
        }
      } catch (error) {
        console.log('Could not access page content:', error);
      }
      
      Object.entries(patterns).forEach(([category, pattern]) => { // Check patterns against URL and page content
        const foundInUrl = pattern.keywords.filter(keyword => 
          fullUrl.includes(keyword) || domain.includes(keyword)
        );
        
        const foundInContent = pageContent ? pattern.keywords.filter(keyword => 
          pageContent.includes(keyword)
        ) : [];
        
        const allFound = [...new Set([...foundInUrl, ...foundInContent])];
        
        if (allFound.length > 0) {
          score += pattern.score;
          issues.push(`${pattern.message}: ${allFound.slice(0, 3).join(', ')}`);
        }
      });
      
      const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click']; // Additional security checks
      suspiciousTlds.forEach(tld => {
        if (domain.endsWith(tld)) {
          score += 15;
          issues.push(`Suspicious domain extension: ${tld}`);
        }
      });
      
      const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link', 'ow.ly']; // Check for URL shorteners
      if (shorteners.some(shortener => domain.includes(shortener))) {
        score += 10;
        issues.push('URL shortener detected');
      }
      
      if (domain.includes('xn--')) { // Check for suspicious domain characteristics
        score += 15;
        issues.push('Internationalized domain (potential homograph attack)');
      }
      
      const subdomains = domain.split('.'); // Check for excessive subdomains
      if (subdomains.length > 4) {
        score += 10;
        issues.push('Excessive subdomains detected');
      }
      
      let level = 'safe'; // Determine risk level using same thresholds as background.js
      let status = 'Safe';
      
      if (score >= 70) {
        level = 'danger';
        status = 'High Risk';
      } else if (score >= 40) {
        level = 'warning';
        status = 'Medium Risk';
      }
      
      return { status, level, issues, score };
      
    } catch (error) {
      console.error('Scan error:', error);
      return {
        status: 'Error',
        level: 'warning',
        issues: ['Unable to scan URL'],
        score: 0
      };
    }
  },

  showAlert(scanResult) { // Show security alert
    const message = `Security Alert!\n\nWebsite: ${this.currentUrl}\nRisk Level: ${scanResult.status}\nScore: ${scanResult.score}/100\nIssues: ${scanResult.issues.join(', ')}\n\nDo you want to continue?`;
    
    if (confirm(message)) {
      console.log('User chose to continue despite warning');
    } else if (this.settings.blockingEnabled) {
      window.close();
    }
  },

  showMessage(text, type = 'info') { // Show message to user
    document.querySelectorAll('.message').forEach(msg => msg.remove()); // Remove existing messages
    
    const message = document.createElement('div');
    message.className = `message ${type}`;
    message.textContent = text;
    
    const activeTab = document.querySelector('.tab.active'); // Insert at the top of the current tab
    if (activeTab) {
      activeTab.insertBefore(message, activeTab.firstChild);
      
      setTimeout(() => { // Auto-remove after 3 seconds
        message.remove();
      }, 3000);
    }
  },

  addToList(listType) { // Add domain to whitelist/blacklist
    const input = document.getElementById(`${listType}Input`);
    if (!input) return;
    
    const rawDomain = input.value.trim();
    if (!rawDomain) {
      this.showMessage('Please enter a domain', 'error');
      return;
    }
    
    const domain = this.normalizeDomain(rawDomain);
    if (!domain) {
      this.showMessage('Please enter a valid domain', 'error');
      return;
    }
    
    if (!this.isValidDomain(domain)) {
      this.showMessage('Please enter a valid domain format (e.g., example.com or *.example.com)', 'error');
      return;
    }
    
    const list = listType === 'whitelist' ? this.whitelist : this.blacklist;
    const otherList = listType === 'whitelist' ? this.blacklist : this.whitelist;
    
    if (list.some(d => d.toLowerCase() === domain.toLowerCase())) { // Check if domain already exists
      this.showMessage('Domain already exists in this list', 'error');
      return;
    }
    
    if (otherList.some(d => d.toLowerCase() === domain.toLowerCase())) { // Check if domain exists in opposite list
      const otherListName = listType === 'whitelist' ? 'blacklist' : 'whitelist';
      this.showMessage(`Domain exists in ${otherListName}. Remove it from there first.`, 'warning');
      return;
    }
    
    list.push(domain); // Add domain to list
    this.saveLists();
    this.renderLists();
    
    input.value = ''; // Clear input and validation
    input.classList.remove('valid', 'invalid');
    const errorElement = input.parentElement.querySelector('.input-error');
    if (errorElement) errorElement.remove();
    
    this.showMessage(`${domain} added to ${listType}`, 'success');
    
    if (listType === 'whitelist') { // Rescan if whitelist was updated
      setTimeout(() => this.scanCurrentSite(), 500);
    }
  },

  removeFromList(listType, domain) { // Remove domain from list
    if (confirm(`Are you sure you want to remove "${domain}" from the ${listType}?`)) {
      const list = listType === 'whitelist' ? this.whitelist : this.blacklist;
      const index = list.findIndex(d => d.toLowerCase() === domain.toLowerCase());
      
      if (index > -1) {
        list.splice(index, 1);
        this.saveLists();
        this.renderLists();
        this.showMessage(`${domain} removed from ${listType}`, 'success');
        
        if (listType === 'whitelist') { // Rescan if whitelist was updated
          setTimeout(() => this.scanCurrentSite(), 500);
        }
      }
    }
  },

  renderLists() { // Render domain lists
    ['whitelist', 'blacklist'].forEach(listType => {
      const ul = document.getElementById(`${listType}Items`);
      if (!ul) return;
      
      ul.innerHTML = '';
      const list = listType === 'whitelist' ? this.whitelist : this.blacklist;
      
      if (list.length === 0) {
        const li = document.createElement('li');
        li.className = 'empty-list';
        li.textContent = `No domains in ${listType}`;
        li.style.fontStyle = 'italic';
        li.style.color = '#666';
        ul.appendChild(li);
        return;
      }
      
      const sortedList = [...list].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())); // Sort domains alphabetically
      
      sortedList.forEach(domain => {
        const li = document.createElement('li');
        
        const domainSpan = document.createElement('span');
        domainSpan.className = 'domain-name';
        domainSpan.textContent = domain;
        
        if (domain.startsWith('*.')) { // Add wildcard indicator
          domainSpan.classList.add('wildcard');
          domainSpan.title = 'Wildcard pattern - matches all subdomains';
        }
        
        const removeBtn = document.createElement('button');
        removeBtn.className = 'remove-btn';
        removeBtn.textContent = 'Remove';
        removeBtn.title = `Remove ${domain} from ${listType}`;
        
        li.appendChild(domainSpan);
        li.appendChild(removeBtn);
        ul.appendChild(li);
        
        removeBtn.addEventListener('click', () => { // Add event listener to the remove button
          this.removeFromList(listType, domain);
        });
      });
    });
  },

  async reportSite() { // Report suspicious site
    const urlInput = document.getElementById('reportUrl');
    const reasonInput = document.getElementById('reportreason_flagged');
    const reportBtn = document.getElementById('reportBtn');
    
    const url = urlInput?.value.trim() || '';
    const reason_flagged = reasonInput?.value.trim() || '';
    
    if (!url) {
      this.showMessage('Please enter a URL to report', 'error');
      return;
    }
    if (!reason_flagged) {
      this.showMessage('Please provide a reason for reporting', 'error');
      return;
    }
    if (!this.isValidUrl(url)) {
      this.showMessage('Please enter a valid URL', 'error');
      return;
    }
    
    if (reportBtn) { // Show loading state
      reportBtn.textContent = 'Submitting...';
      reportBtn.disabled = true;
    }
    
    try {
      const response = await fetch('https://backend-uwk4.onrender.com/report', { // Send report to backend
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url,
          reason_flagged: reason_flagged,
          email: null, // Optional: add email field to form if needed
          timestamp: new Date().toISOString()
        })
      });
      
      const result = await response.json();
      
      if (response.ok && result.success) {
        urlInput.value = ''; // Clear form on success
        reasonInput.value = '';
        
        this.showMessage('Report submitted successfully! Thank you for helping keep users safe.', 'success');
        
        await this.logWarning(url, reason_flagged); // Also log the warning to track patterns
        
      } else {
        throw new Error(result.error || 'Failed to submit report');
      }
      
    } catch (error) {
      console.error('Error submitting report:', error);
      this.showMessage(`Failed to submit report: ${error.message}`, 'error');
      
      console.log('Report (failed to submit):', { // Fallback: log locally for debugging
        url, 
        reason_flagged, 
        timestamp: new Date().toISOString(),
        error: error.message 
      });
    } finally {
      if (reportBtn) { // Reset button state
        reportBtn.textContent = 'Submit Report';
        reportBtn.disabled = false;
      }
    }
  },

  async logWarning(url, reason_flagged) { // Log warning to backend for pattern analysis
    try {
      await fetch('https://backend-uwk4.onrender.com/logs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domain_url: url,
          detection_score: 80, // High score for user-reported sites
          keywords: reason_flagged.split(' ').slice(0, 10), // Extract keywords from reason_flagged
          source: 'user_report'
        })
      });
    } catch (error) {
      console.error('Error logging warning:', error);
      // Don't show error to user for this background operation
    }
  },

  saveSettingsFromForm() { // Save settings from form
    const systemLang = document.getElementById('systemLang');
    const alertLang = document.getElementById('alertLang');
    
    if (systemLang && systemLang.value.trim()) {
      this.settings.systemLang = systemLang.value.trim();
    }
    if (alertLang && alertLang.value.trim()) {
      this.settings.alertLang = alertLang.value.trim();
    }
    
    this.saveSettings();
  },

  rescanSite() { // Rescan current site
    this.scanCurrentSite();
    this.showMessage('Site rescanned', 'success');
  }
};

window.FountainScan = FountainScan; // Expose for debugging

document.addEventListener("DOMContentLoaded", () => { // Initialize when DOM is loaded
  FountainScan.init();
});