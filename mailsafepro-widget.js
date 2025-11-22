/**
 * MailSafePro Email Validation Widget (Premium)
 * v2.0.0
 * 
 * "The Industry Standard for Email Validation"
 */
(function (window, document) {
    'use strict';

    // --- Constants & Config ---
    const DEFAULTS = {
        apiUrl: 'https://email-validation-api-jlra.onrender.com/email',
        debounceTime: 600,
        checkSmtp: false,
        theme: 'default', // 'default' | 'minimal'
        showIcons: true,
        showSuggestions: true,
        messages: {
            valid: 'Email válido',
            invalid: 'Email inválido',
            risky: 'Email de riesgo detectado',
            disposable: 'No aceptamos emails temporales',
            loading: 'Verificando...',
            suggestion: '¿Quisiste decir {suggestion}?',
            error: 'Error de conexión'
        }
    };

    const ICONS = {
        valid: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
        invalid: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`,
        risky: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`,
        loading: `<svg class="msp-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>`
    };

    const STYLES = `
        .msp-wrapper {
            position: relative;
            width: 100%;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        /* Input State Styles */
        .msp-input-valid { border-color: #10B981 !important; padding-right: 40px !important; transition: border-color 0.3s ease; }
        .msp-input-invalid { border-color: #EF4444 !important; padding-right: 40px !important; transition: border-color 0.3s ease; }
        .msp-input-risky { border-color: #F59E0B !important; padding-right: 40px !important; transition: border-color 0.3s ease; }
        .msp-input-loading { padding-right: 40px !important; }

        /* Floating Icon */
        .msp-icon {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            width: 20px;
            height: 20px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s ease, transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
            z-index: 10;
        }
        .msp-icon.msp-visible { opacity: 1; transform: translateY(-50%) scale(1); }
        .msp-icon svg { width: 100%; height: 100%; }
        
        .msp-icon-valid { color: #10B981; }
        .msp-icon-invalid { color: #EF4444; }
        .msp-icon-risky { color: #F59E0B; }
        .msp-icon-loading { color: #6B7280; }

        /* Message & Suggestions */
        .msp-feedback {
            margin-top: 6px;
            font-size: 13px;
            line-height: 1.4;
            min-height: 0;
            opacity: 0;
            transform: translateY(-5px);
            transition: all 0.3s ease;
            overflow: hidden;
            max-height: 0;
        }
        .msp-feedback.msp-visible {
            opacity: 1;
            transform: translateY(0);
            max-height: 40px; /* Allow expansion */
        }

        .msp-text-valid { color: #059669; font-weight: 500; }
        .msp-text-invalid { color: #DC2626; font-weight: 500; }
        .msp-text-risky { color: #D97706; font-weight: 500; }
        .msp-text-loading { color: #6B7280; }

        /* Suggestion Chip */
        .msp-suggestion {
            display: inline-flex;
            align-items: center;
            background-color: #EFF6FF;
            color: #2563EB;
            padding: 4px 8px;
            border-radius: 12px;
            cursor: pointer;
            font-weight: 500;
            margin-top: 4px;
            border: 1px solid #DBEAFE;
            transition: all 0.2s ease;
        }
        .msp-suggestion:hover {
            background-color: #DBEAFE;
            transform: translateY(-1px);
        }
        .msp-suggestion strong { margin-left: 4px; text-decoration: underline; }

        /* Animation */
        @keyframes msp-spin { 
            to { transform: rotate(360deg); } 
        }
        .msp-spin { animation: msp-spin 1s linear infinite; }
    `;

    // --- Class Definition ---
    class MailSafeProWidget {
        constructor(inputElement, options = {}) {
            this.input = inputElement;
            this.options = { ...DEFAULTS, ...options };
            this.state = {
                lastValue: '',
                timer: null,
                isValid: false,
                isTyping: false
            };

            if (!this.input) {
                console.error('MailSafePro: Input element not found.');
                return;
            }

            this._init();
        }

        _init() {
            this._injectStyles();
            this._wrapInput();
            this._bindEvents();
        }

        _injectStyles() {
            if (!document.getElementById('msp-styles')) {
                const style = document.createElement('style');
                style.id = 'msp-styles';
                style.textContent = STYLES;
                document.head.appendChild(style);
            }
        }

        _wrapInput() {
            // Create wrapper
            this.wrapper = document.createElement('div');
            this.wrapper.className = 'msp-wrapper';

            // Insert wrapper before input
            this.input.parentNode.insertBefore(this.wrapper, this.input);

            // Move input into wrapper
            this.wrapper.appendChild(this.input);

            // Create Icon Container
            this.iconEl = document.createElement('div');
            this.iconEl.className = 'msp-icon';
            this.wrapper.appendChild(this.iconEl);

            // Create Feedback Container
            this.feedbackEl = document.createElement('div');
            this.feedbackEl.className = 'msp-feedback';
            this.feedbackEl.setAttribute('aria-live', 'polite');
            this.wrapper.appendChild(this.feedbackEl);
        }

        _bindEvents() {
            this.input.addEventListener('input', this._handleInput.bind(this));
            this.input.addEventListener('blur', () => {
                if (this.input.value.trim()) {
                    this._validate(this.input.value.trim(), true);
                }
            });
        }

        _handleInput(e) {
            const value = e.target.value.trim();

            // Clear timer
            if (this.state.timer) clearTimeout(this.state.timer);

            // Reset if empty
            if (!value) {
                this._resetUI();
                return;
            }

            // Syntax check
            if (!this._isValidSyntax(value)) {
                this._updateUI('invalid', this.options.messages.invalid);
                return;
            }

            // Show loading state immediately if configured
            this._updateUI('loading', this.options.messages.loading);

            // Debounce API call
            this.state.timer = setTimeout(() => {
                if (value !== this.state.lastValue) {
                    this._validate(value);
                }
            }, this.options.debounceTime);
        }

        _isValidSyntax(email) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        }

        async _validate(email, force = false) {
            if (!email) return;
            if (email === this.state.lastValue && !force) return;

            this.state.lastValue = email;

            // --- DEMO MODE ---
            if (this.options.apiKey === 'DEMO_KEY_123') {
                console.info('MailSafePro: Running in DEMO MODE');
                this._updateUI('loading', this.options.messages.loading);

                // Simulate network delay
                await new Promise(resolve => setTimeout(resolve, 800));

                // Mock Logic
                let mockResponse = { valid: true, risk_score: 0.1 };

                if (email.includes('gmil.com')) {
                    mockResponse = {
                        valid: false,
                        suggested_fixes: { typo_detected: true, suggested_email: email.replace('gmil.com', 'gmail.com') }
                    };
                } else if (email.includes('temp')) {
                    mockResponse = { valid: false, is_disposable: true };
                } else if (email.includes('risk')) {
                    mockResponse = { valid: true, risk_score: 0.8 };
                } else if (email.includes('fail')) {
                    mockResponse = { valid: false };
                }

                this._processResult(mockResponse);
                return;
            }
            // -----------------

            try {
                const response = await fetch(this.options.apiUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': this.options.apiKey
                    },
                    body: JSON.stringify({
                        email: email,
                        check_smtp: this.options.checkSmtp
                    })
                });

                if (!response.ok) throw new Error(`API Error: ${response.status}`);

                const data = await response.json();
                this._processResult(data);

            } catch (error) {
                console.error('MailSafePro Error:', error);
                this._updateUI('error', this.options.messages.error);
            }
        }

        _processResult(data) {
            // 1. Check for Typo Suggestion
            if (data.suggested_fixes && data.suggested_fixes.typo_detected) {
                this._showSuggestion(data.suggested_fixes.suggested_email);
                return;
            }

            // 2. Check Validity
            if (!data.valid) {
                this._updateUI('invalid', data.detail || this.options.messages.invalid);
                return;
            }

            // 3. Check Disposable
            if (data.is_disposable) {
                this._updateUI('invalid', this.options.messages.disposable);
                return;
            }

            // 4. Check Risk Score
            const risk = data.risk_score || 0;
            if (risk > 0.7) {
                this._updateUI('risky', this.options.messages.risky);
            } else if (risk > 0.4) {
                this._updateUI('risky', 'Email con riesgo moderado');
            } else {
                this._updateUI('valid', this.options.messages.valid);
            }
        }

        _showSuggestion(suggestedEmail) {
            this._resetClasses();

            // Set Warning State
            this.input.classList.add('msp-input-risky');
            this.iconEl.innerHTML = ICONS.risky;
            this.iconEl.className = 'msp-icon msp-visible msp-icon-risky';

            // Build Suggestion UI
            this.feedbackEl.innerHTML = '';

            const suggestionBtn = document.createElement('div');
            suggestionBtn.className = 'msp-suggestion';
            suggestionBtn.innerHTML = this.options.messages.suggestion.replace('{suggestion}', `<strong>${suggestedEmail}</strong>`);

            suggestionBtn.onclick = () => {
                this.input.value = suggestedEmail;
                this.input.focus();
                this._validate(suggestedEmail, true); // Re-validate immediately
            };

            this.feedbackEl.appendChild(suggestionBtn);
            this.feedbackEl.classList.add('msp-visible');
        }

        _updateUI(status, message) {
            this._resetClasses();

            // Update Input Class
            this.input.classList.add(`msp-input-${status}`);

            // Update Icon
            if (this.options.showIcons) {
                this.iconEl.innerHTML = ICONS[status] || '';
                this.iconEl.className = `msp-icon msp-visible msp-icon-${status}`;
            }

            // Update Message
            this.feedbackEl.textContent = message;
            this.feedbackEl.className = `msp-feedback msp-visible msp-text-${status}`;

            // Accessibility
            this.input.setAttribute('aria-invalid', status === 'invalid' || status === 'risky');
        }

        _resetUI() {
            this._resetClasses();
            this.iconEl.classList.remove('msp-visible');
            this.feedbackEl.classList.remove('msp-visible');
            this.state.lastValue = '';
        }

        _resetClasses() {
            this.input.classList.remove(
                'msp-input-valid', 'msp-input-invalid', 'msp-input-risky', 'msp-input-loading'
            );
        }
    }

    // --- Auto Initialization ---
    function autoInit() {
        const scriptTag = document.currentScript || document.querySelector('script[src*="widget.js"]');
        if (!scriptTag) return;

        const apiKey = scriptTag.getAttribute('data-api-key');
        const inputId = scriptTag.getAttribute('data-input-id');

        if (apiKey && inputId) {
            const input = document.getElementById(inputId);
            if (input) {
                const options = {
                    apiKey: apiKey,
                    checkSmtp: scriptTag.getAttribute('data-check-smtp') === 'true',
                    debounceTime: parseInt(scriptTag.getAttribute('data-debounce') || '600')
                };

                const baseUrl = scriptTag.getAttribute('data-base-url');
                if (baseUrl) {
                    options.apiUrl = baseUrl.replace(/\/+$/, '') + '/email';
                }

                new MailSafeProWidget(input, options);
            }
        }
    }

    // Expose to Window
    window.MailSafeProWidget = MailSafeProWidget;

    // Run Auto Init
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', autoInit);
    } else {
        autoInit();
    }

})(window, document);
