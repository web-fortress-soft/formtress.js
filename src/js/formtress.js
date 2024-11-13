/**
 * Formtress.js - Enterprise Form Security Library
 * Because security starts with the form.
 * @author: Resti Guay
 * Version: 0.1.0
 * Features:
 * - Automatic form discovery and protection
 * - Grade A security
 * - XSS, SQL Injection, CSRF protection
 * - Input validation and sanitization
 * - Rate limiting
 * - Event monitoring
 * - Error handling
 * - Accessibility support
 * - Configuration validation
 * - Configuration schema
 * - Deep merge utility
 * - Error types
 * - Secure configuration store
 * - Secure function creation
 * - Debounce utility
 * - Event listeners
 * - Weakening protection detection and prevention
 * - Configuration schema validation
 * - Configuration loading from JSON
 * - Secure configuration deep merge utility
 * - Private storage
 * - Seured forms storage
 * - Private key symbol
 * - Configuration object
 * - Security patterns object
 */

const Formtress = (() => {
    
    // 1. Freeze core prototypes
    Object.freeze(Object.prototype);
    Object.freeze(Array.prototype);
    // Private storage
    const privateStore = new WeakMap();
    const securedForms = new WeakSet();
    const PRIVATE_KEY = Symbol('formtressPrivate');

    // Security patterns and configurations
    const SECURITY_CONFIG = {
        patterns: {
            xss: {
                patterns: [
                    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi.source,
                    /javascript:/gi.source,
                    /data:/gi.source,
                    /vbscript:/gi.source,
                    /on\w+\s*=/gi.source,
                    /<\s*iframe/gi.source,
                    /<\s*object/gi.source,
                    /<\s*embed/gi.source,
                    /expression\s*\(/gi.source,
                    /url\s*\(/gi.source,
                    /eval\s*\(/gi.source
                ],
                description: 'XSS attempt detected'
            },
            sql: {
                patterns: [
                    /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|MODIFY|TRUNCATE|EXEC|DECLARE)\b/gi.source,
                    /'.*--/gi.source,
                    /;\s*$/gi.source,
                    /\/\*[\s\S]*?\*\//g.source,
                    /\bOR\b\s*['"\d]/gi.source,
                    /\bAND\b\s*['"\d]/gi.source
                ],
                description: 'SQL injection attempt detected'
            },
            prototype: {
                patterns: [
                    /__proto__/g.source,
                    /constructor\s*\./g.source,
                    /prototype\s*\./g.source,
                    /Object\.assign/g.source,
                    /Object\.defineProperty/g.source,
                    /Object\.setPrototypeOf/g.source
                ],
                description: 'Prototype pollution attempt detected'
            },
            path: {
                patterns: [
                    /\.\.\//g.source,
                    /\.\.\\/g.source,
                    /~\//g.source,
                    /\/etc\//g.source,
                    /\/proc\//g.source,
                    /\/sys\//g.source,
                    /\/var\/log\//g.source
                ],
                description: 'Path traversal attempt detected'
            },
            command: {
                patterns: [
                    /\$\([^)]*\)/g.source,
                    /`[^`]*`/g.source,
                    /system\(/g.source,
                    /exec\(/g.source,
                    /shell_exec\(/g.source,
                    /passthru\(/g.source
                ],
                description: 'Command injection attempt detected'
            }
        },
        validation: {
            email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.source,
            phone: /^\+?[\d\s-]{10,}$/.source,
            url: /^https?:\/\/[\w\-.]+(:\d+)?([\/\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/.source,
            alphanumeric: /^[a-zA-Z0-9]*$/.source,
            numbers: /^[0-9]*$/.source,
            date: /^\d{4}-\d{2}-\d{2}$/.source
        },
        rateLimit: {
            enabled: true,
            window: 1000,
            max: 30,
            windowMs: 60000
        },
        feedback: {
            showSuccess: true,
            showError: true,
            successSymbol: '✓',
            errorSymbol: '✗',
            successColor: '#4CAF50',
            errorColor: '#ff4444',
            customStyles: null
        },
        accessibility: {
            ariaLive: 'polite',
            useAriaInvalid: true,
            useAriaDescribedBy: true
        },
        csrf: {
            enabled: false,
            fieldName: '_csrf',
            validateOnSubmit: true
        },
        hooks: {
            beforeValidation: null,
            afterValidation: null,
            beforeSubmit: null,
            afterSubmit: null,
            onError: null
        }
    };
    // Configuration schema for validation
    const CONFIG_SCHEMA = {
        security: {
            patterns: {
                xss: {
                    enabled: Boolean,
                    patterns: Array,
                    description: String
                },
                sql: {
                    enabled: Boolean,
                    patterns: Array,
                    description: String
                }
            },
            validation: {
                email: RegExp,
                phone: RegExp,
                url: RegExp,
                alphanumeric: RegExp,
                numbers: RegExp,
                date: RegExp
            },
            rateLimit: {
                enabled: Boolean,
                window: Number,
                max: Number,
                windowMs: Number
            }
        },
        feedback: {
            showSuccess: Boolean,
            showError: Boolean,
            successSymbol: String,
            errorSymbol: String,
            successColor: String,
            errorColor: String,
            customStyles: Object
        },
        accessibility: {
            ariaLive: String,
            useAriaInvalid: Boolean,
            useAriaDescribedBy: Boolean
        },
        csrf: {
            enabled: Boolean,
            fieldName: String,
            validateOnSubmit: Boolean
        }
    };

    class ConfigurationError extends Error {
        constructor(message, path = []) {
            super(message);
            this.name = 'ConfigurationError';
            this.path = path;
        }
    }
    // Validate configuration against schema
    const validateConfig = (config, schema = CONFIG_SCHEMA, path = []) => {
        if (!config || typeof config !== 'object') {
            throw new ConfigurationError('Configuration must be an object', path);
        }

        const validatedConfig = {};

        for (const [key, value] of Object.entries(config)) {
            const currentPath = [...path, key];
            
            if (!schema[key]) {
                console.warn(`Unknown configuration key: ${currentPath.join('.')}`);
                continue;
            }

            const expectedType = schema[key];

            if (expectedType === Boolean) {
                if (typeof value !== 'boolean') {
                    throw new ConfigurationError(
                        `Expected boolean for ${currentPath.join('.')} but got ${typeof value}`,
                        currentPath
                    );
                }
                validatedConfig[key] = value;
            } else if (expectedType === Number) {
                if (typeof value !== 'number' || !isFinite(value)) {
                    throw new ConfigurationError(
                        `Expected number for ${currentPath.join('.')} but got ${typeof value}`,
                        currentPath
                    );
                }
                validatedConfig[key] = value;
            } else if (expectedType === String) {
                if (typeof value !== 'string') {
                    throw new ConfigurationError(
                        `Expected string for ${currentPath.join('.')} but got ${typeof value}`,
                        currentPath
                    );
                }
                validatedConfig[key] = value;
            } else if (expectedType === RegExp) {
                try {
                    validatedConfig[key] = value instanceof RegExp ? 
                        value : new RegExp(value);
                } catch (error) {
                    throw new ConfigurationError(
                        `Invalid regular expression for ${currentPath.join('.')}`,
                        currentPath
                    );
                }
            } else if (expectedType === Array) {
                if (!Array.isArray(value)) {
                    throw new ConfigurationError(
                        `Expected array for ${currentPath.join('.')} but got ${typeof value}`,
                        currentPath
                    );
                }
                validatedConfig[key] = [...value];
            } else if (expectedType === Object) {
                validatedConfig[key] = { ...value };
            } else if (typeof expectedType === 'object') {
                validatedConfig[key] = validateConfig(value, expectedType, currentPath);
            }
        }

        return validatedConfig;
    };

    // Apply configuration to a form
    const applyConfig = (form, config) => {
        if (!(form instanceof HTMLFormElement)) {
            throw new ConfigurationError('Target must be a form element');
        }

        const formtress = form.formtress || Formtress.secure(form);
        const validatedConfig = validateConfig(config);
        
        try {
            formtress.updateConfig(validatedConfig);
            configStore.set(form, validatedConfig);
            
            // Dispatch configuration change event
            configEvents.dispatchEvent(new CustomEvent('configUpdate', {
                detail: {
                    form,
                    config: validatedConfig
                }
            }));

            return true;
        } catch (error) {
            console.error('Failed to apply configuration:', error);
            throw error;
        }
    };

    // Load configuration from JSON
    const loadConfigFromJson = async (url) => {
        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const config = await response.json();
            return validateConfig(config);
        } catch (error) {
            console.error('Failed to load configuration:', error);
            throw error;
        }
    };

    // Add a deep merge utility
    const deepMerge = (target, source) => {
        // Handle null/undefined cases
        if (!source) return target;
        if (!target) return source;
    
        // Create a new object for the result
        const result = { ...target };
    
        // Helper to check if a key is safe
        const isSafeKey = (key) => {
            const unsafeKeys = [
                '__proto__',
                'constructor',
                'prototype',
                'hasOwnProperty',
                'isPrototypeOf',
                'propertyIsEnumerable',
                'toLocaleString',
                'toString',
                'valueOf'
            ];
            return !unsafeKeys.includes(key);
        };
    
        // Helper to check if value is a plain object
        const isPlainObject = (obj) => {
            if (!obj || typeof obj !== 'object') return false;
            const proto = Object.getPrototypeOf(obj);
            return proto === Object.prototype || proto === null;
        };
    
        // Iterate only own properties
        Object.keys(source).forEach(key => {
            // Skip unsafe keys
            if (!isSafeKey(key)) {
                console.warn(`Attempted prototype pollution detected with key: ${key}`);
                return;
            }
    
            const sourceValue = source[key];
            const targetValue = target[key];
    
            // Handle nested objects
            if (isPlainObject(sourceValue) && isPlainObject(targetValue)) {
                result[key] = deepMerge(targetValue, sourceValue);
            } else {
                result[key] = sourceValue;
            }
        });
    
        return result;
    };
    // Error types
    class FormtressError extends Error {
        constructor(message, type) {
            super(message);
            this.name = 'FormtressError';
            this.type = type;
        }
    }

    // Core security class
    class SecurityCore {
        constructor(config) {
            this.violations = [];
            this.csrfEnabled = false;
            this.csrfFieldName = '_csrf';
            this.config = deepMerge(SECURITY_CONFIG, config);
            this.patterns = this.cloneSecurityPatterns(SECURITY_CONFIG.patterns);
        }

        /**
         * Clone security patterns to create mutable RegExp instances
         * @param {Object} patterns - The patterns to clone
         * @returns {Object} Cloned patterns
         */
        cloneSecurityPatterns(patterns) {
            const clonedPatterns = {};
            
            for (const [key, value] of Object.entries(patterns)) {
                clonedPatterns[key] = {
                    patterns: value.patterns.map(pattern => {
                        if (pattern instanceof RegExp) {
                            // Create a new RegExp with the same pattern and flags
                            return new RegExp(pattern.source, pattern.flags);
                        }
                        return pattern;
                    }),
                    description: value.description
                };
            }
            
            return clonedPatterns;
        }
        
       /**
         * Validate input
         * @param {string} value - The value to validate
         * @param {string} type - The type of input
         * @returns {boolean} Whether the input is valid
         */
        validateInput(value, type = 'text') {
            if (typeof value !== 'string') {
                value = String(value);
            }

            // Check for security violations using cloned patterns
            for (const [key, pattern] of Object.entries(this.patterns)) {
                // Create fresh RegExp instances for each test to avoid lastIndex issues
                const patterns = pattern.patterns.map(p => 
                    p instanceof RegExp ? new RegExp(p.source, p.flags) : new RegExp(p)
                );

                if (patterns.some(p => p.test(value))) {
                    throw new FormtressError(pattern.description, key);
                }
            }

            // Validate based on type using fresh RegExp instances
            if (SECURITY_CONFIG.validation[type]) {
                const validationPattern = new RegExp(SECURITY_CONFIG.validation[type]);
                if (!validationPattern.test(value)) {
                    throw new FormtressError(`Invalid ${type} format`, 'validation');
                }
            }

            return true;
        }
        /**
         * Sanitize input
         * @param {string} value - The value to sanitize
         * @returns {string} The sanitized value
         */
        sanitizeInput(value) {
            if (typeof value !== 'string') {
                return value;
            }

            // Use fresh RegExp instances for each replacement
            return value
                .replace(new RegExp(/[<>]/g), '')
                .replace(new RegExp(/javascript:/gi), '')
                .replace(new RegExp(/data:/gi), '')
                .replace(new RegExp(/vbscript:/gi), '')
                .replace(new RegExp(/on\w+=/gi), '')
                .trim();
        }
        /**
         * Validate CSRF
         * @param {HTMLElement} form - The form to validate
         * @returns {boolean} Whether the CSRF validation is successful
         */
        validateCsrf(form) {
            if (!this.csrfEnabled) {
                console.warn('Formtress: CSRF protection is not enabled. Call enableCsrf() to enable it.');
                return true;
            }

            const csrfToken = form.querySelector(`input[name="${this.csrfFieldName}"]`);
            if (!csrfToken) {
                throw new FormtressError('CSRF token is missing', 'csrf');
            }
            
            if (!csrfToken.value) {
                throw new FormtressError('CSRF token is empty', 'csrf');
            }

            return true;
        }
    }

    // Rate limiter implementation
    class RateLimiter {
        constructor() {
            this.attempts = new Map();
        }
        /**
         * Check the rate limit
         * @param {string} identifier - The identifier to check
         * @returns {boolean} Whether the limit is exceeded
         */
        checkLimit(identifier) {
            const now = Date.now();
            const windowMs = SECURITY_CONFIG.rateLimit.windowMs;
            const maxAttempts = SECURITY_CONFIG.rateLimit.max;

            const userAttempts = this.attempts.get(identifier) || [];
            const recentAttempts = userAttempts.filter(timestamp => 
                now - timestamp < windowMs
            );

            if (recentAttempts.length >= maxAttempts) {
                return false;
            }

            recentAttempts.push(now);
            this.attempts.set(identifier, recentAttempts);
            return true;
        }
    }
    // Add secure configuration store
    const SecureFormtressConfigInjector = (() => {
        const initialConfigs = new WeakMap();
        const lockedFeatures = new WeakMap();
        
        const deepFreeze = (obj) => {
            if (obj && typeof obj === 'object') {
                Object.keys(obj).forEach(prop => {
                    if (obj[prop] && typeof obj[prop] === 'object') {
                        deepFreeze(obj[prop]);
                    }
                });
                return Object.freeze(obj);
            }
            return obj;
        };
        
        const getNestedValue = (obj, path) => {
            return path.reduce((current, key) => 
                current && current[key] !== undefined ? current[key] : undefined, obj);
        };

        const isSecurityWeakened = (originalConfig, newConfig) => {
            const criticalPaths = [
                ['security', 'patterns', 'xss', 'enabled'],
                ['security', 'patterns', 'sql', 'enabled'],
                ['security', 'rateLimit', 'enabled'],
                ['csrf', 'enabled'],
                ['security', 'validation', 'enabled']
            ];
            
            for (const criticalPath of criticalPaths) {
                const originalValue = getNestedValue(originalConfig, criticalPath);
                const newValue = getNestedValue(newConfig, criticalPath);
                
                if (originalValue === true && newValue === false) {
                    throw new FormtressError(
                        `Attempt to disable security feature: ${criticalPath.join('.')}`,
                        'security_downgrade'
                    );
                }
            }
            
            // Check rate limit values
            const originalRate = getNestedValue(originalConfig, ['security', 'rateLimit', 'max']);
            const newRate = getNestedValue(newConfig, ['security', 'rateLimit', 'max']);
            
            if (originalRate && newRate && newRate > originalRate * 2) {
                throw new FormtressError(
                    'Attempt to significantly weaken rate limiting',
                    'security_downgrade'
                );
            }
            
            return false;
        };

        return {
            lockConfig: (form, config) => {
                if (initialConfigs.has(form)) {
                    throw new FormtressError('Form already has locked configuration', 'config_error');
                }
                
                const frozenConfig = deepFreeze({ ...config });
                initialConfigs.set(form, frozenConfig);
                
                lockedFeatures.set(form, new Set([
                    'security.patterns.xss.enabled',
                    'security.patterns.sql.enabled',
                    'security.rateLimit.enabled',
                    'csrf.enabled',
                    'security.validation.enabled'
                ]));
                
                return frozenConfig;
            },
            
            validateConfigUpdate: (form, newConfig) => {
                if (!initialConfigs.has(form)) {
                    throw new FormtressError('Form not initialized with secure configuration', 'config_error');
                }
                
                const originalConfig = initialConfigs.get(form);
                const locked = lockedFeatures.get(form);
                
                isSecurityWeakened(originalConfig, newConfig);
                
                // Create safe config preserving locked values
                const safeConfig = { ...newConfig };
                locked.forEach(path => {
                    const keys = path.split('.');
                    const originalValue = getNestedValue(originalConfig, keys);
                    let current = safeConfig;
                    
                    keys.forEach((key, index) => {
                        if (index === keys.length - 1) {
                            current[key] = originalValue;
                        } else {
                            current[key] = current[key] || {};
                            current = current[key];
                        }
                    });
                });
                
                return deepFreeze(safeConfig);
            }
        };
    })();
    // Main Formtress class
    class FormtressForm {
        
        constructor(form, customConfig = {}) {
            const defaultConfig = {
                validation: {   
                    debounce: 300, // Default 300ms debounce
                    async: true,
                    ...customConfig.validation
                }
            };
            // Merge custom config with defaults
            const config = deepMerge(SECURITY_CONFIG, defaultConfig);
            
            const secureConfig = SecureFormtressConfigInjector.lockConfig(form, config);
            const secure = {
                form: form,
                config: config,
                security: new SecurityCore(config.security),
                rateLimiter: config.rateLimit.enabled ? new RateLimiter(config.rateLimit) : null,
                fields: new Map(),
                lastSubmit: 0,
                debouncedValidations: new Map() // Store debounced functions per field
            };
            
            privateStore.set(this, secure);
            this.initializeForm();
        }
        /**
         * Get the current configuration
         * @returns {Object} The current configuration
         */
        getConfig() {
            return JSON.parse(JSON.stringify(privateStore.get(this).config));
        }
        /**
         * Initialize the form
         */
        initializeForm() {
            const state = privateStore.get(this);
            const form = state.form;

            // Add necessary attributes
            form.setAttribute('novalidate', 'true');
            form.dataset.formtressSecured = 'true';

            // Initialize fields
            form.querySelectorAll('input, textarea, select').forEach(field => {
                this.initializeField(field);
            });

            // Handle form submission
            form.addEventListener('submit', (e) => this.handleSubmit(e));

            // Observe form changes
            this.observeFormChanges(form);
        }
        /**
         * Update the config at runtime
         * @param {object} newConfig - The new configuration
         */
        updateConfig(newConfig) {
            const state = privateStore.get(this);
            const form = state.form;
            
            try {
                // Validate and secure the new configuration
                const safeConfig = SecureFormtressConfigInjector.validateConfigUpdate(form, newConfig);
                
                // Apply the safe configuration
                state.config = safeConfig;
                
                // Reinitialize components that depend on config
                if (safeConfig.security) {
                    state.security = new SecurityCore(safeConfig.security);
                }
                if (safeConfig.rateLimit) {
                    state.rateLimiter = safeConfig.rateLimit.enabled ? 
                        new RateLimiter(safeConfig.rateLimit) : null;
                }
                
                // Update existing fields with new config
                this.updateFieldsWithConfig();
                
                return this.getConfig();
            } catch (error) {
                console.error('Configuration update failed:', error);
                // Emit security event
                const event = new CustomEvent('formtress:security', {
                    detail: {
                        type: 'config_violation',
                        message: error.message,
                        config: newConfig
                    }
                });
                state.form.dispatchEvent(event);
                throw error;
            }
        }
        /**
         * Update fields with new config
         */
        updateFieldsWithConfig() {
            const state = privateStore.get(this);
            state.fields.forEach((field, name) => {
                this.updateFieldConfig(name, field);
            });
        }
        /**
         * Update field config
         * @param {string} name - The name of the field
         * @param {object} field - The field to update
         */
        updateFieldConfig(name, field) {
            const state = privateStore.get(this);
            const config = state.config;
    
            // Update result container styles
            if (field.resultContainer) {
                if (config.feedback.customStyles) {
                    Object.assign(field.resultContainer.style, config.feedback.customStyles);
                }
                
                // Update ARIA attributes
                if (config.accessibility.useAriaLive) {
                    field.resultContainer.setAttribute('aria-live', config.accessibility.ariaLive);
                }
            }
    
            // Update field attributes
            if (config.accessibility.useAriaInvalid) {
                field.element.setAttribute('aria-invalid', 'false');
            }
        }
        /**
         * Initialize a field
         * @param {HTMLElement} field - The field to initialize
         */
        initializeField(field) {
            if (field.type === 'submit' || field.type === 'reset' || field.dataset.formtressSecured) {
                return;
            }
    
            const state = privateStore.get(this);
            const name = field.name || field.id;
    
            // Mark as secured
            field.dataset.formtressSecured = 'true';
    
            // Create result container
            const resultContainer = document.createElement('div');
            resultContainer.className = 'formtress-result';
            resultContainer.setAttribute('aria-live', 'polite');
            field.parentNode.insertBefore(resultContainer, field.nextSibling);
    
            // Create debounced validation function for this field
            const debouncedValidation = debounce(
                () => this.validateField(name),
                state.config.validation.debounce
            );
    
            // Store field info
            state.fields.set(name, {
                element: field,
                type: field.type,
                resultContainer,
                validate: debouncedValidation
            });
    
            // Store debounced function reference
            state.debouncedValidations.set(name, debouncedValidation);
    
            // Add event listeners
            field.addEventListener('input', () => {
                // Show loading state immediately
                this.showResult(resultContainer, 'loading', 'Validating...');
                // Call debounced validation
                state.debouncedValidations.get(name)();
            });
    
            // Immediate validation on blur
            field.addEventListener('blur', () => this.validateField(name));
        }

        /**
         * Update the debounce time for a field
         * @param {string} fieldName - The name of the field to update
         * @param {number} time - The new debounce time in milliseconds
         */
        updateDebounceTime(fieldName, time) {
            const state = privateStore.get(this);
            const field = state.fields.get(fieldName);
            
            if (field) {
                // Create new debounced function with updated time
                const newDebouncedValidation = debounce(
                    () => this.validateField(fieldName),
                    time
                );
                
                state.debouncedValidations.set(fieldName, newDebouncedValidation);
                field.validate = newDebouncedValidation;
            }
        }

        /**
         * Clear all debounced validations
         * 
         */
        clearDebouncedValidations() {
            const state = privateStore.get(this);
            state.debouncedValidations.forEach((debouncedFn, fieldName) => {
                if (debouncedFn.clear) {
                    debouncedFn.clear();
                }
            });
        }

        /**
         * Validate a field
         * @param {string} fieldName - The name of the field to validate
         * @returns {Object} The validation result
         */
        async validateField(fieldName) {
            const state = privateStore.get(this);
            const field = state.fields.get(fieldName);

            if (!field) return null;

            try {
                const value = field.element.value;
                const type = field.element.type;

                // Validate and sanitize
                state.security.validateInput(value, type);
                const sanitized = state.security.sanitizeInput(value);

                // Update field with sanitized value
                if (value !== sanitized) {
                    field.element.value = sanitized;
                }

                this.showResult(field.resultContainer, 'success');
                return { success: true, value: sanitized };

            } catch (error) {
                console.error('Formtress: Validation error:', error);
                this.showResult(field.resultContainer, 'error', error.message);
                return { success: false, error: error.message };
            }
        }

        /**
         * Show the result of a validation
         * @param {HTMLElement} container - The container to show the result in
         * @param {string} type - The type of result to show
         * @param {string} message - The message to show
         */
        showResult(container, type, message = '') {
            const state = privateStore.get(this);
            const config = state.config.feedback;
            
            container.className = `formtress-result formtress-${type}`;
            
            if (type === 'loading') {
                container.textContent = '⟳';
                container.style.color = '#666';
                // Add loading animation
               //container.style.animation = 'formtress-spin 1s linear infinite';
                return;
            }
            container.className = `formtress-result formtress-${type}`;
            container.textContent = type === 'success' ? '✓' : `✗ ${message}`;
            container.style.color = type === 'success' ? '#4CAF50' : '#ff4444';
        }
        /**
         * Destroy the form
         */
        destroy() {
            const state = privateStore.get(this);
            // Clear all debounced functions
            this.clearDebouncedValidations();
            // Remove all event listeners
            state.fields.forEach((field) => {
                field.element.removeEventListener('input', field.validate);
                field.element.removeEventListener('blur', () => this.validateField(field.name));
            });
            // Clear WeakMap entry
            privateStore.delete(this);
        }
        /**
         * Handle form submission
         * @param {Event} event - The submit event
         * @returns {boolean} Whether the submission was successful
         */
        async handleSubmit(event) {
            event.preventDefault();
            const state = privateStore.get(this);

            try {
                // Validate CSRF token
                state.security.validateCsrf(state.form);
                // Check rate limiting
                if (!state.rateLimiter.checkLimit('submit')) {
                    alert('Please wait before submitting again');
                    return false;
                }

                // Validate all fields
                const validations = await Promise.all(
                    Array.from(state.fields.keys()).map(name => this.validateField(name))
                );

                if (validations.every(v => v.success)) {
                    // Form is valid - collect sanitized data
                    const formData = new FormData(state.form);
                    const sanitizedData = {};

                    for (const [name, value] of formData.entries()) {
                        sanitizedData[name] = state.security.sanitizeInput(value);
                    }

                    // Trigger success event with sanitized data
                    const successEvent = new CustomEvent('formtress:success', {
                        detail: { data: sanitizedData }
                    });
                    state.form.dispatchEvent(successEvent);

                    return true;
                }

                return false;
            } catch (error) {
                console.error('Formtress: Submission error:', error);
                if (error.type === 'csrf') {
                    console.error('Formtress: CSRF validation failed:', error.message);
                    const csrfEvent = new CustomEvent('formtress:csrfError', {
                        detail: { error: error.message }
                    });
                    state.form.dispatchEvent(csrfEvent);
                    return false;
                }
                throw error;
            }
        }

        /**
         * Observe form changes
         * @param {HTMLElement} form - The form to observe
         */
        observeFormChanges(form) {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node instanceof HTMLElement) {
                            if (node.matches('input, textarea, select')) {
                                this.initializeField(node);
                            }
                            node.querySelectorAll('input, textarea, select')
                                .forEach(field => this.initializeField(field));
                        }
                    });
                });
            });

            observer.observe(form, {
                childList: true,
                subtree: true
            });
        }
    }

    /**
     * DOMProtector class
     */
    class DOMProtector {
        constructor(config) {
            this.config = config;
            this.protectedElements = new WeakMap();
            this.observer = null;
        }
        /**
         * Sanitize content
         * @param {string} content - The content to sanitize
         * @returns {string} The sanitized content
         */
        sanitizeContent(content) {
            if (typeof content !== 'string') {
                return content;
            }
    
            // Apply all XSS patterns
            const sanitized = SECURITY_CONFIG.patterns.xss.patterns.reduce(
                (result, pattern) => result.replace(pattern, ''),
                content
            );
    
            return sanitized
                .replace(/[<>]/g, '')
                .replace(/javascript:/gi, '')
                .replace(/data:/gi, '')
                .replace(/vbscript:/gi, '')
                .replace(/on\w+=/gi, '')
                .trim();
        }
        /**
         * Validate a URL
         * @param {string} url - The URL to validate
         * @returns {boolean} Whether the URL is valid
         */
        validateUrl(url) {
            if (!url) return false;
            
            try {
                const urlObj = new URL(url);
                // Check protocol
                if (!['http:', 'https:'].includes(urlObj.protocol)) {
                    return false;
                }
                
                // Check for XSS in URL
                if (SECURITY_CONFIG.patterns.xss.patterns.some(pattern => 
                    pattern.test(decodeURIComponent(url)))) {
                    return false;
                }
                
                return true;
            } catch {
                return false;
            }
        }
        /**
         * Protect an element
         * @param {Element} element - The element to protect
         * @param {object} options - The options for protection
         */
        protectElement(element, options = {}) {
            const config = {
                allowHtml: false,
                allowUrls: false,
                urlWhitelist: [],
                ...options
            };
    
            this.protectedElements.set(element, config);
    
            // Override innerHTML setter
            const originalInnerHTML = Object.getOwnPropertyDescriptor(
                Element.prototype,
                'innerHTML'
            );
    
            Object.defineProperty(element, 'innerHTML', {
                set: (content) => {
                    const sanitized = config.allowHtml ? 
                        this.sanitizeHtml(content) : 
                        this.sanitizeContent(content);
                    originalInnerHTML.set.call(element, sanitized);
                },
                get: originalInnerHTML.get
            });
    
            // Monitor attribute changes
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.type === 'attributes') {
                        this.validateAttribute(element, mutation.attributeName);
                    }
                });
            });
    
            observer.observe(element, {
                attributes: true
            });
        }
        /**
         * Validate an attribute
         * @param {Element} element - The element to validate
         * @param {string} attrName - The attribute name to validate
         */
        validateAttribute(element, attrName) {
            const value = element.getAttribute(attrName);
            
            // Check for dangerous attributes
            if (/^on/i.test(attrName)) {
                element.removeAttribute(attrName);
                this.reportViolation('eventHandler', { element, attribute: attrName });
                return;
            }
    
            // Check URLs in attributes
            if (['src', 'href', 'action', 'formaction'].includes(attrName)) {
                if (!this.validateUrl(value)) {
                    element.removeAttribute(attrName);
                    this.reportViolation('unsafeUrl', { element, attribute: attrName, value });
                }
            }
        }
        /**
         * Sanitize HTML
         * @param {string} html - The HTML content to sanitize
         * @returns {string} The sanitized HTML content
         */
        sanitizeHtml(html) {
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const safe = this.sanitizeNode(doc.body);
            return safe.innerHTML;
        }
        /**
         * Sanitize a node
         * @param {Node} node - The node to sanitize
         * @returns {Node} The sanitized node
         */
        sanitizeNode(node) {
            const allowedTags = ['p', 'b', 'i', 'u', 'strong', 'em', 'span', 'div', 'a'];
            const allowedAttrs = ['href', 'class', 'id', 'title'];
    
            const clean = document.createElement(
                allowedTags.includes(node.tagName.toLowerCase()) ? 
                    node.tagName.toLowerCase() : 
                    'span'
            );
    
            // Copy allowed attributes
            Array.from(node.attributes).forEach(attr => {
                if (allowedAttrs.includes(attr.name)) {
                    if (attr.name === 'href') {
                        if (this.validateUrl(attr.value)) {
                            clean.setAttribute(attr.name, attr.value);
                        }
                    } else {
                        clean.setAttribute(attr.name, attr.value);
                    }
                }
            });
    
            // Recursively clean child nodes
            Array.from(node.childNodes).forEach(child => {
                if (child.nodeType === Node.TEXT_NODE) {
                    clean.appendChild(document.createTextNode(child.textContent));
                } else if (child.nodeType === Node.ELEMENT_NODE) {
                    clean.appendChild(this.sanitizeNode(child));
                }
            });
    
            return clean;
        }
        /**
         * Report a violation
         * @param {string} type - The type of violation
         * @param {object} details - The details of the violation
         */
        reportViolation(type, details) {
            const event = new CustomEvent('formtress:violation', {
                detail: {
                    type,
                    timestamp: new Date(),
                    ...details
                }
            });
            document.dispatchEvent(event);
        }
    }
    class SanitizationConfig {
        constructor(options = {}) {
            this.tags = {
                allow: options.allowTags || ['p', 'b', 'i', 'u', 'strong', 'em', 'span', 'div', 'a', 'ul', 'ol', 'li'],
                deny: options.denyTags || ['script', 'style', 'iframe', 'object', 'embed', 'form'],
                custom: options.customTags || {}
            };
    
            this.attributes = {
                allow: options.allowAttributes || ['class', 'id', 'href', 'title', 'alt', 'src'],
                deny: options.denyAttributes || ['onload', 'onerror', 'style'],
                custom: options.customAttributes || {}
            };
    
            this.urls = {
                allowedProtocols: options.allowedProtocols || ['http:', 'https:'],
                allowedDomains: options.allowedDomains || [],
                allowDataUrls: options.allowDataUrls || false,
                allowRelative: options.allowRelative || true
            };
    
            this.css = {
                allowStyles: options.allowStyles || false,
                allowClasses: options.allowClasses || true,
                allowedProperties: options.allowedProperties || [
                    'color', 'background-color', 'font-size', 'text-align',
                    'margin', 'padding', 'border', 'display'
                ]
            };
    
            this.transformations = {
                urlTransform: options.urlTransform || ((url) => url),
                textTransform: options.textTransform || ((text) => text),
                attributeTransform: options.attributeTransform || ((name, value) => ({ name, value }))
            };
    
            this.mode = options.mode || 'strict'; // 'strict', 'relaxed', 'custom'
        }
    }
    
    class ContentSanitizer {
        constructor(config) {
            this.config = new SanitizationConfig(config);
        }
        /**
         * Sanitize content
         * @param {string} content - The content to sanitize
         * @param {object} options - The options for sanitization
         * @returns {string} The sanitized content
         */
        sanitizeContent(content, options = {}) {
            if (typeof content !== 'string') {
                return content;
            }
    
            const localConfig = { ...this.config, ...options };
    
            // Apply custom text transformations
            content = localConfig.transformations.textTransform(content);
    
            // Handle different modes
            switch (localConfig.mode) {
                case 'strict':
                    return this.strictSanitize(content);
                case 'relaxed':
                    return this.relaxedSanitize(content);
                case 'custom':
                    return this.customSanitize(content, localConfig);
                default:
                    return this.strictSanitize(content);
            }
        }
    
        /**
         * Sanitize HTML
         * @param {string} html - The HTML content to sanitize
         * @param {object} options - The options for sanitization
         * @returns {string} The sanitized HTML content
         */
        sanitizeHtml(html, options = {}) {
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const safe = this.sanitizeNode(doc.body, options);
            return safe.innerHTML;
        }
        /**
         * Sanitize a node
         * @param {Node} node - The node to sanitize
         * @param {object} options - The options for sanitization
         * @returns {Node} The sanitized node
         */
        sanitizeNode(node, options = {}) {
            const config = { ...this.config, ...options };
            const clean = this.createSafeNode(node, config);
    
            if (!clean) return document.createTextNode('');
    
            // Handle attributes
            this.sanitizeAttributes(node, clean, config);
    
            // Handle styles if allowed
            if (config.css.allowStyles) {
                this.sanitizeStyles(clean, config);
            }
    
            // Recursively handle children
            Array.from(node.childNodes).forEach(child => {
                if (child.nodeType === Node.TEXT_NODE) {
                    const safeText = config.transformations.textTransform(child.textContent);
                    clean.appendChild(document.createTextNode(safeText));
                } else if (child.nodeType === Node.ELEMENT_NODE) {
                    const safeChild = this.sanitizeNode(child, config);
                    if (safeChild) {
                        clean.appendChild(safeChild);
                    }
                }
            });
    
            return clean;
        }
        /**
         * Create a safe node
         * @param {Node} node - The node to create
         * @param {object} config - The configuration for the node
         * @returns {Node} The created node
         */
        createSafeNode(node, config) {
            const tagName = node.tagName.toLowerCase();
    
            // Check if tag is explicitly denied
            if (config.tags.deny.includes(tagName)) {
                return null;
            }
    
            // Check if tag is allowed
            if (config.tags.allow.includes(tagName)) {
                return document.createElement(tagName);
            }
    
            // Check custom tag handlers
            if (config.tags.custom[tagName]) {
                return config.tags.custom[tagName](node);
            }
    
            // Default to span for unknown elements in relaxed mode
            if (config.mode === 'relaxed') {
                return document.createElement('span');
            }
    
            return null;
        }
        /**
         * Sanitize attributes
         * @param {Node} node - The node to sanitize
         * @param {Node} clean - The clean node
         * @param {object} config - The configuration for the node
         */
        sanitizeAttributes(node, clean, config) {
            Array.from(node.attributes).forEach(attr => {
                const { name, value } = attr;
    
                // Skip denied attributes
                if (config.attributes.deny.includes(name)) {
                    return;
                }
    
                // Handle allowed attributes
                if (config.attributes.allow.includes(name)) {
                    if (this.isValidAttributeValue(name, value, config)) {
                        const transformed = config.transformations.attributeTransform(name, value);
                        clean.setAttribute(transformed.name, transformed.value);
                    }
                }
    
                // Handle custom attribute handlers
                if (config.attributes.custom[name]) {
                    const customValue = config.attributes.custom[name](value, node);
                    if (customValue) {
                        clean.setAttribute(name, customValue);
                    }
                }
            });
        }
        /**
         * Sanitize styles
         * @param {Element} element - The element to sanitize
         * @param {object} config - The configuration for the styles
         */
        sanitizeStyles(element, config) {
            const style = element.getAttribute('style');
            if (!style) return;
    
            const safeStyles = style
                .split(';')
                .map(rule => rule.trim())
                .filter(rule => {
                    const [property] = rule.split(':');
                    return config.css.allowedProperties.includes(property.trim());
                })
                .join('; ');
    
            if (safeStyles) {
                element.setAttribute('style', safeStyles);
            } else {
                element.removeAttribute('style');
            }
        }
        /**
         * Validate an attribute value
         * @param {string} name - The attribute name
         * @param {string} value - The attribute value
         * @param {object} config - The configuration for the attribute
         * @returns {boolean} Whether the attribute value is valid
         */
        isValidAttributeValue(name, value, config) {
            // Handle URLs
            if (['src', 'href', 'action'].includes(name)) {
                return this.isValidUrl(value, config.urls);
            }
    
            // Handle classes
            if (name === 'class' && !config.css.allowClasses) {
                return false;
            }
    
            // Handle IDs
            if (name === 'id') {
                return /^[a-zA-Z][\w-]*$/.test(value);
            }
    
            return true;
        }
        /**
         * Validate a URL
         * @param {string} url - The URL to validate
         * @param {object} urlConfig - The configuration for the URL
         * @returns {boolean} Whether the URL is valid
         */
        isValidUrl(url, urlConfig) {
            try {
                // Handle relative URLs
                if (urlConfig.allowRelative && url.startsWith('/')) {
                    return true;
                }
    
                const urlObj = new URL(url);
    
                // Check protocol
                if (!urlConfig.allowedProtocols.includes(urlObj.protocol)) {
                    return false;
                }
    
                // Check domain if whitelist exists
                if (urlConfig.allowedDomains.length > 0) {
                    return urlConfig.allowedDomains.some(domain => 
                        urlObj.hostname === domain || 
                        urlObj.hostname.endsWith(`.${domain}`)
                    );
                }
    
                // Handle data URLs
                if (url.startsWith('data:') && !urlConfig.allowDataUrls) {
                    return false;
                }
    
                return true;
            } catch {
                return false;
            }
        }
        /**
         * Strict sanitization
         * @param {string} content - The content to sanitize
         * @returns {string} The sanitized content
         */
        strictSanitize(content) {
            return content
                .replace(/<[^>]*>/g, '') // Remove all HTML tags
                .replace(/&\w+;/g, '') // Remove HTML entities
                .replace(/javascript:/gi, '')
                .replace(/data:/gi, '')
                .replace(/vbscript:/gi, '')
                .replace(/on\w+=/gi, '')
                .trim();
        }
        /**
         * Relaxed sanitization
         * @param {string} content - The content to sanitize
         * @returns {string} The sanitized content
         */
        relaxedSanitize(content) {
            // Allow basic formatting but remove scripts and dangerous content
            return content
                .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
                .replace(/on\w+="[^"]*"/gi, '')
                .replace(/javascript:/gi, '')
                .replace(/data:/gi, '')
                .replace(/vbscript:/gi, '')
                .trim();
        }
        /**
         * Custom sanitization
         * @param {string} content - The content to sanitize
         * @param {object} config - The configuration for the sanitization
         * @returns {string} The sanitized content
         */
        customSanitize(content, config) {
            // Apply custom sanitization rules
            let result = content;
    
            // Apply custom tag filters
            Object.keys(config.tags.custom).forEach(tag => {
                const handler = config.tags.custom[tag];
                const regex = new RegExp(`<${tag}[^>]*>.*?</${tag}>`, 'gi');
                result = result.replace(regex, (match) => handler(match) || '');
            });
    
            // Apply custom attribute filters
            Object.keys(config.attributes.custom).forEach(attr => {
                const handler = config.attributes.custom[attr];
                const regex = new RegExp(`${attr}="[^"]*"`, 'gi');
                result = result.replace(regex, (match) => {
                    const value = match.split('=')[1].slice(1, -1);
                    const sanitized = handler(value);
                    return sanitized ? `${attr}="${sanitized}"` : '';
                });
            });
    
            return result;
        }
    }
    // Global observer for automatic form discovery
    class FormtressObserver {
        constructor() {
            this.startObserving();
            this.secureExistingForms();
        }
        /**
         * Start observing the document for form changes
         */
        startObserving() {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node instanceof HTMLElement) {
                            if (node.nodeName === 'FORM' && !node.dataset.formtressSecured) {
                                this.secureForm(node);
                            }
                            node.querySelectorAll('form:not([data-formtress-secured])')
                                .forEach(form => this.secureForm(form));
                        }
                    });
                });
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true
            });
        }

        /**
         * Secure existing forms
         */
        secureExistingForms() {
            document.querySelectorAll('form:not([data-formtress-secured])')
                .forEach(form => this.secureForm(form));
        }

        /**
         * Secure a form
         * @param {HTMLElement} form - The form to secure
         */
        secureForm(form) {
            try {
                if (!securedForms.has(form)) {
                    new FormtressForm(form);
                    securedForms.add(form);
                }
            } catch (error) {               
                console.error('Formtress: Failed to secure form', error);
            }
        }
    }
    const createSecureFunction = (code) => {
        const secureFunction = Function.prototype.bind.call(
            Function.prototype.call,
            function() {
                'use strict';
                return code.apply(this, arguments);
            }
        );
        
        Object.freeze(secureFunction);
        return secureFunction;
    };
    
    
    const debounce = (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    };

    // Initialize observer
    const observer = new FormtressObserver();

    // Public API
    return Object.freeze({
        // Manual form security if needed
        secure: createSecureFunction((formEl) => {
            const form = typeof formEl === 'string' 
                ? document.getElementById(formEl)
                : formEl;
            return new FormtressForm(form);
        }),
        // Get security patterns (read-only)
        getPatterns: () => JSON.parse(JSON.stringify(SECURITY_CONFIG.patterns)),
        // Version info
        version: '0.1.0',    
        // Add DOM protection utility methods
        dom: {
            protectElement: (element, options) => {
                const protector = new DOMProtector(SECURITY_CONFIG);
                return protector.protectElement(element, options);
            },
            sanitize: (content) => {
                const protector = new DOMProtector(SECURITY_CONFIG);
                return protector.sanitizeContent(content);
            },
            sanitizeHtml: (content) => {
                const protector = new DOMProtector(SECURITY_CONFIG);
                return protector.sanitizeHtml(content);
            },
            validateUrl: (url) => {
                const protector = new DOMProtector(SECURITY_CONFIG);
                return protector.validateUrl(url);
            },
            /**
             * Content sanitization methods
             * Example:
             * const sanitizer = Formtress.sanitize.createSanitizer({
             *   mode: 'strict',
             *   allowedProtocols: ['http:', 'https:']
             * });
             */
            createSanitizer: (config) => new ContentSanitizer(config),
            /**
             * Sanitize content
             * Example:
             * const sanitized = Formtress.sanitize.sanitize(content, {
             *   mode: 'strict',
             *   allowedProtocols: ['http:', 'https:']
             * });
             */
            sanitizeContent: (content, options) => {
                const sanitizer = new ContentSanitizer(options);
                return sanitizer.sanitizeContent(content);
            },
            /**
             * Sanitize HTML
             * Example:
             * const sanitizedHtml = Formtress.sanitize.sanitizeHtml(html, {
             *   mode: 'strict',
             *   allowedProtocols: ['http:', 'https:']
             * });
             */
            sanitizeHtmlContent: (content, options) => {
                const sanitizer = new ContentSanitizer(options);
                return sanitizer.sanitizeHtml(content);
            }
        },
        /**
         * Inject configuration into a form or forms
         * @param {HTMLFormElement|HTMLFormElement[]|string} target - Form(s) or selector
         * @param {Object} config - Configuration to inject
         */
        inject: (target, config) => {
            const forms = target instanceof HTMLFormElement ? [target] :
                         typeof target === 'string' ? document.querySelectorAll(target) :
                         Array.isArray(target) ? target : [];

            const results = Array.from(forms).map(form => {
                try {
                    return applyConfig(form, config);
                } catch (error) {
                    console.error(`Failed to inject config for form:`, form, error);
                    return false;
                }
            });

            return results.every(Boolean);
        },

        /**
         * Load and inject configuration from a JSON URL
         * @param {HTMLFormElement|HTMLFormElement[]|string} target - Form(s) or selector
         * @param {string} url - URL to load configuration from
         */
        injectFromUrl: async (target, url) => {
            try {
                const config = await loadConfigFromJson(url);
                return FormtressConfigInjector.inject(target, config);
            } catch (error) {
                console.error('Failed to inject configuration from URL:', error);
                throw error;
            }
        },

        /**
         * Subscribe to configuration changes
         * @param {function} callback - Callback function
         */
        onConfigChange: (callback) => {
            configEvents.addEventListener('configUpdate', (event) => {
                callback(event.detail.form, event.detail.config);
            });
        },

        /**
         * Get current configuration for a form
         * @param {HTMLFormElement} form - Target form
         */
        getConfig: (form) => {
            return configStore.get(form);
        },

        /**
         * Validate configuration without applying it
         * @param {Object} config - Configuration to validate
         */
        validateConfig: (config) => {
            return validateConfig(config);
        }
    });
})();
// Add CSS for loading animation
const style = document.createElement('style');
style.textContent = `
    @keyframes formtress-spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    .formtress-loading {
        display: inline-block;
    }
`;
document.head.appendChild(style);
// Auto-initialize when the DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Formtress is already initialized through the FormtressObserver
        console.log('Formtress: Initialized through DOMContentLoaded');
    });
} else {
    // DOM is already ready, Formtress is initialized through the IIFE
    console.log('Formtress: Initialized through IIFE. DOM is already ready. Security is a must, all the time!');
}