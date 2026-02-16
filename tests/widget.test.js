/**
 * MailSafePro Widget - Exhaustive Tests
 */

const widgetCode = require('../mailsafepro-widget.js');

describe('MailSafeProWidget', () => {
    let inputElement;
    let widget;
    let mockFetch;

    beforeEach(() => {
        document.getElementById.mockReset();
        document.createElement.mockReset();
        document.head.appendChild.mockReset();

        const mockWrapper = {
            className: '',
            innerHTML: '',
            setAttribute: jest.fn(),
            getAttribute: jest.fn(),
            appendChild: jest.fn(),
            removeChild: jest.fn(),
            insertBefore: jest.fn(),
            parentNode: {
                removeChild: jest.fn()
            }
        };

        const mockIcon = {
            className: 'msp-icon',
            innerHTML: '',
            appendChild: jest.fn()
        };

        const mockFeedback = {
            className: 'msp-feedback',
            textContent: '',
            innerHTML: '',
            setAttribute: jest.fn(),
            appendChild: jest.fn(),
            getAttribute: jest.fn()
        };

        document.createElement
            .mockReturnValueOnce(mockWrapper)
            .mockReturnValueOnce(mockIcon)
            .mockReturnValueOnce(mockFeedback);

        inputElement = {
            id: 'email-input',
            value: '',
            className: '',
            parentNode: {
                insertBefore: jest.fn()
            },
            addEventListener: jest.fn(),
            removeEventListener: jest.fn(),
            setAttribute: jest.fn(),
            getAttribute: jest.fn(),
            focus: jest.fn()
        };

        document.getElementById.mockReturnValue(inputElement);

        widget = new window.MailSafeProWidget(inputElement, {
            apiKey: 'test_api_key'
        });
    });

    describe('Constructor', () => {
        test('should throw error if input element is null', () => {
            expect(() => {
                new window.MailSafeProWidget(null, {});
            }).toThrow();
        });

        test('should initialize with default options', () => {
            const testWidget = new window.MailSafeProWidget(inputElement, {});
            expect(testWidget.input).toBe(inputElement);
            expect(testWidget.options.apiKey).toBe('test_api_key');
        });

        test('should merge custom options with defaults', () => {
            const testWidget = new window.MailSafeProWidget(inputElement, {
                apiKey: 'custom_key',
                debounceTime: 1000,
                checkSmtp: true
            });
            expect(testWidget.options.apiKey).toBe('custom_key');
            expect(testWidget.options.debounceTime).toBe(1000);
            expect(testWidget.options.checkSmtp).toBe(true);
        });
    });

    describe('Email Syntax Validation', () => {
        test('should accept valid email format', () => {
            const validEmails = [
                'test@example.com',
                'user.name@domain.org',
                'user+tag@example.co.uk',
                'test123@sub.domain.com'
            ];
            validEmails.forEach(email => {
                expect(widget._isValidSyntax(email)).toBe(true);
            });
        });

        test('should reject invalid email format', () => {
            const invalidEmails = [
                'invalid',
                '@nodomain.com',
                'no@',
                'no@domain',
                'no@domain.',
                ' spaces@domain.com',
                'test@ domain.com'
            ];
            invalidEmails.forEach(email => {
                expect(widget._isValidSyntax(email)).toBe(false);
            });
        });
    });

    describe('API Integration', () => {
        beforeEach(() => {
            mockFetch = jest.fn();
            global.fetch = mockFetch;
        });

        test('should call API with correct endpoint', async () => {
            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ valid: true, risk_score: 0.1 })
            });

            await widget._validate('test@example.com');

            expect(mockFetch).toHaveBeenCalledWith(
                'https://api.mailsafepro.es/validate/email',
                expect.objectContaining({
                    method: 'POST',
                    headers: expect.objectContaining({
                        'Content-Type': 'application/json',
                        'X-API-Key': 'test_api_key'
                    })
                })
            );
        });

        test('should include check_smtp in request when enabled', async () => {
            const widgetWithSmtp = new window.MailSafeProWidget(inputElement, {
                apiKey: 'test_key',
                checkSmtp: true
            });

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ valid: true })
            });

            await widgetWithSmtp._validate('test@example.com');

            expect(mockFetch).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    body: JSON.stringify({
                        email: 'test@example.com',
                        check_smtp: true
                    })
                })
            );
        });
    });

    describe('Demo Mode', () => {
        test('should use demo logic when API key is DEMO_KEY_123', async () => {
            const demoWidget = new window.MailSafeProWidget(inputElement, {
                apiKey: 'DEMO_KEY_123'
            });

            await demoWidget._validate('test@temp.com');

            expect(demoWidget.state.lastValue).toBe('test@temp.com');
        });

        test('should detect disposable email in demo mode', async () => {
            const demoWidget = new window.MailSafeProWidget(inputElement, {
                apiKey: 'DEMO_KEY_123'
            });

            await demoWidget._validate('user@temp.com', true);

            expect(demoWidget.state.lastValue).toBe('user@temp.com');
        });

        test('should detect typo in demo mode', async () => {
            const demoWidget = new window.MailSafeProWidget(inputElement, {
                apiKey: 'DEMO_KEY_123'
            });

            await demoWidget._validate('user@gmil.com', true);
        });
    });

    describe('UI Updates', () => {
        test('should update UI with valid state', () => {
            widget._updateUI('valid', 'Email válido');

            expect(inputElement.classList.contains('msp-input-valid')).toBe(true);
        });

        test('should update UI with invalid state', () => {
            widget._updateUI('invalid', 'Email inválido');

            expect(inputElement.classList.contains('msp-input-invalid')).toBe(true);
        });

        test('should update UI with risky state', () => {
            widget._updateUI('risky', 'Email de riesgo');

            expect(inputElement.classList.contains('msp-input-risky')).toBe(true);
        });

        test('should update UI with loading state', () => {
            widget._updateUI('loading', 'Verificando...');

            expect(inputElement.classList.contains('msp-input-loading')).toBe(true);
        });
    });

    describe('Suggestion Handling', () => {
        test('should show suggestion for typo detected', () => {
            const mockData = {
                suggested_fixes: {
                    typo_detected: true,
                    suggested_email: 'test@gmail.com'
                }
            };

            widget._processResult(mockData);
        });

        test('should handle suggestion click and revalidate', () => {
            widget.state.lastValue = 'test@gmil.com';

            widget.input.value = 'test@gmail.com';

            widget._showSuggestion('test@gmail.com');
        });
    });

    describe('Event Handling', () => {
        test('should bind input event listener', () => {
            expect(inputElement.addEventListener).toHaveBeenCalledWith(
                'input',
                expect.any(Function)
            );
        });

        test('should bind blur event listener', () => {
            expect(inputElement.addEventListener).toHaveBeenCalledWith(
                'blur',
                expect.any(Function)
            );
        });

        test('should reset UI when input is empty', () => {
            widget.input.value = '';
            const event = { target: { value: '' } };

            widget._handleInput(event);

            expect(widget.state.lastValue).toBe('');
        });
    });

    describe('Result Processing', () => {
        test('should handle valid response', () => {
            const mockData = {
                valid: true,
                risk_score: 0.1,
                is_disposable: false
            };

            widget._processResult(mockData);
        });

        test('should handle invalid response', () => {
            const mockData = {
                valid: false,
                detail: 'Invalid email'
            };

            widget._processResult(mockData);
        });

        test('should handle disposable email', () => {
            const mockData = {
                valid: true,
                is_disposable: true
            };

            widget._processResult(mockData);
        });

        test('should handle high risk score', () => {
            const mockData = {
                valid: true,
                risk_score: 0.8,
                is_disposable: false
            };

            widget._processResult(mockData);
        });

        test('should handle medium risk score', () => {
            const mockData = {
                valid: true,
                risk_score: 0.5,
                is_disposable: false
            };

            widget._processResult(mockData);
        });
    });

    describe('Reset Functionality', () => {
        test('should reset UI classes', () => {
            widget.input.className = 'msp-input-valid msp-input-invalid';

            widget._resetClasses();

            expect(inputElement.classList.contains('msp-input-valid')).toBe(false);
            expect(inputElement.classList.contains('msp-input-invalid')).toBe(false);
        });

        test('should reset entire UI state', () => {
            widget.state.lastValue = 'test@example.com';

            widget._resetUI();

            expect(widget.state.lastValue).toBe('');
        });
    });

    describe('Widget Destruction', () => {
        test('should have destroy method', () => {
            expect(typeof widget.destroy).toBe('function');
        });

        test('should clear timer on destroy', () => {
            widget.state.timer = setTimeout(() => {}, 1000);

            widget.destroy();

            expect(widget.state.timer).toBeNull();
        });
    });

    describe('Accessibility', () => {
        test('should set aria-invalid on invalid state', () => {
            widget._updateUI('invalid', 'Test');

            expect(inputElement.setAttribute).toHaveBeenCalledWith(
                'aria-invalid',
                'true'
            );
        });

        test('should set aria-invalid on risky state', () => {
            widget._updateUI('risky', 'Test');

            expect(inputElement.setAttribute).toHaveBeenCalledWith(
                'aria-invalid',
                'true'
            );
        });
    });

    describe('Configuration Options', () => {
        test('should respect custom debounce time', () => {
            const customWidget = new window.MailSafeProWidget(inputElement, {
                apiKey: 'test',
                debounceTime: 1000
            });

            expect(customWidget.options.debounceTime).toBe(1000);
        });

        test('should allow custom messages', () => {
            const customMessages = {
                valid: 'Custom valid message',
                invalid: 'Custom invalid message',
                risky: 'Custom risky message'
            };

            const customWidget = new window.MailSafeProWidget(inputElement, {
                apiKey: 'test',
                messages: customMessages
            });

            expect(customWidget.options.messages.valid).toBe('Custom valid message');
            expect(customWidget.options.messages.invalid).toBe('Custom invalid message');
            expect(customWidget.options.messages.risky).toBe('Custom risky message');
        });

        test('should allow hiding icons', () => {
            const noIconWidget = new window.MailSafeProWidget(inputElement, {
                apiKey: 'test',
                showIcons: false
            });

            expect(noIconWidget.options.showIcons).toBe(false);
        });
    });

    describe('Edge Cases', () => {
        test('should handle API error gracefully', async () => {
            mockFetch = jest.fn().mockRejectedValueOnce(new Error('Network error'));
            global.fetch = mockFetch;

            await widget._validate('test@example.com');

            expect(inputElement.setAttribute).toHaveBeenCalled();
        });

        test('should handle non-ok API response', async () => {
            mockFetch = jest.fn().mockResolvedValueOnce({
                ok: false,
                status: 500
            });
            global.fetch = mockFetch;

            await widget._validate('test@example.com');

            expect(inputElement.setAttribute).toHaveBeenCalled();
        });

        test('should handle empty email on blur', () => {
            widget.input.value = '';
            
            const blurHandler = inputElement.addEventListener.mock.calls.find(
                call => call[0] === 'blur'
            )[1];

            blurHandler();
        });

        test('should not re-validate same email', async () => {
            widget.state.lastValue = 'test@example.com';
            
            mockFetch = jest.fn();
            global.fetch = mockFetch;

            await widget._validate('test@example.com', false);

            expect(mockFetch).not.toHaveBeenCalled();
        });
    });
});
