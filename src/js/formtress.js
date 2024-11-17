/**
 * Formtress.js - Enterprise Banking-Grade Form Security Library
 * Version: 1.0.0
 */
(() => {

    const IS_DEVELOPMENT = /^(localhost|127\.0\.0\.192\.168\.)|(:[0-9]{4})/i.test(window.location.host);
    //const IS_DEVELOPMENT = false;
    const Logger = (() => {
        const styles = {
            warning: 'color: #ff9800; font-weight: bold',
            error: 'color: #f44336; font-weight: bold',
            info: 'color: #2196f3; font-weight: bold',
            success: 'color: #4caf50; font-weight: bold'
        };
    
        const icons = {
            warning: '⚠️',
            error: '❌',
            info: 'ℹ️',
            success: '✅'
        };
    
        const formatMessage = (type, path, message) => {
            return `%c${icons[type]} ${path ? `${path}: ` : ''}${message}`;
        };
    
        const log = (type, messages, throwError = false) => {
            if (!IS_DEVELOPMENT) return;
    
            const logMethod = type === 'error' ? console.error : console.warn;
            const title = `Formtress: ${type.charAt(0).toUpperCase() + type.slice(1)}s:`;
    
            if (messages.length) {
                console.group(title);
                
                messages.forEach(msg => {
                    logMethod(
                        formatMessage(type, msg.path, msg.message),
                        styles[type]
                    );
    
                    if (msg.recommendation) {
                        logMethod('     Recommendation:', msg.recommendation);
                    }
    
                    if (msg.description) {
                        logMethod('    Description:', msg.description);
                    }
    
                    if (msg.actual !== undefined) {
                        logMethod('    Provided value:', msg.actual);
                    }
                });
    
                console.groupEnd();
    
                if (throwError) {
                    throw new Error(`${title} ${messages[0].message}`);
                }
            }
        };
    
        return {
            warning: (messages) => log('warning', Array.isArray(messages) ? messages : [messages]),
            error: (messages, throwError = true) => log('error', Array.isArray(messages) ? messages : [messages], throwError),
            info: (messages) => log('info', Array.isArray(messages) ? messages : [messages]),
            success: (messages) => log('success', Array.isArray(messages) ? messages : [messages])
        };
    })();
    
    // Utility Functions
    const deepFreeze = (obj) => {
        if (obj && typeof obj === 'object' && !Object.isFrozen(obj)) {
            Object.keys(obj).forEach(prop => deepFreeze(obj[prop]));
            return Object.freeze(obj);
        }
        return obj;
    };

    const secureDeepMerge = (target, source) => {
        const merged = {};
        [...new Set([...Object.keys(target), ...Object.keys(source)])].forEach(key => {
            if (source[key] instanceof Object && !Array.isArray(source[key])) {
                merged[key] = secureDeepMerge(target[key] || {}, source[key]);
            } else {
                merged[key] = source[key] ?? target[key];
            }
        });
        return deepFreeze(merged);
    };   

    // Core Constants
    const CONFIG_SYMBOL = Symbol('formtressConfig');
    const FORM_FLAG_ID = (() => {
        const array = new Uint8Array(8);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    })();   

    // Error Messages
    const ERROR_MESSAGES = Object.freeze({
        noNoscript: 'Formtress.js: <noscript> element not found. Your site will be vulnerable to attacks.',
        noFormtress: 'Formtress.js should be loaded as the first or second script in the <head> element.',
        noDefer: 'Formtress.js should not be loaded with the defer attribute.',
        noBody: 'Formtress.js should be loaded before the body element.',
        configError: 'Invalid security configuration',
        integrityError: 'Configuration integrity compromised'
    });

    // Private Storage
    const privateStore = new WeakMap();
    const securedForms = new WeakSet();

    // Core Security Measures
    Object.freeze(Object.prototype);
    Object.freeze(Array.prototype);
    Object.freeze(Function.prototype);


const DebugManager = (() => {
    const DEBUG_PROBABILITY = 0.05; // 5% chance to trigger debugger
    const MAX_DEBUG_TIME = 1000; // 1 second max debug time
    let debugStartTime = null;
    let devToolsWasOpened = false;
    let lastReloadTime = Date.now();

    const checkFunctionTiming = () => {
        const start = performance.now();
        debugger;
        return (performance.now() - start) > 100;
    };
    const isDevToolsOpen = () => {
        const threshold = 160;
        return (
            window.outerWidth - window.innerWidth > threshold ||
            window.outerHeight - window.innerHeight > threshold ||
            window.devtools?.open ||
            window.Firebug?.chrome?.isInitialized ||
            checkFunctionTiming() ||
            // Check for console timing
            (() => {
                const start = performance.now();
                console.log('');
                return (performance.now() - start) > 20;
            })()
        );
    };
    
    // Check for DevTools being opened
    const checkDevToolsOpened = () => {
        if (!IS_DEVELOPMENT && isDevToolsOpen()) {
            const now = Date.now();
            
            // If this is the first time or if it's been more than 2 seconds since last reload
            if (!devToolsWasOpened || (now - lastReloadTime > 2000)) {
                devToolsWasOpened = true;
                debugStartTime = now;
                lastReloadTime = now;
                console.log('DevTools opened - triggering debugger');
                debugger;
            }
        } else {
            devToolsWasOpened = false;
            debugStartTime = null;
        }
    };    

    const checkDebugTime = () => {
        const now = performance.now(); // Use performance.now() instead of Date.now()
        
        if (!debugStartTime) {
            debugStartTime = now;
            return;
        }

        if ((now - debugStartTime) > MAX_DEBUG_TIME) {
            try {
                // Try native reload first
                if (window.location.reload.toString().includes('[native code]')) {
                    window.location.reload();
                } else {
                    // Fallback to href reassignment
                    window.location.href = window.location.href;
                }
            } catch(e) {
                // Final fallback
                document.body.innerHTML = '';
                window.location = window.location.href;
            }
        }
    };
    const maybeDebug = (context) => {
        if (IS_DEVELOPMENT) return;
    
        checkDevToolsOpened();
    
        if (isDevToolsOpen()) {
            checkDebugTime();
    
            if (Math.random() < DEBUG_PROBABILITY) {
                console.log(`Debug triggered in: ${context}`);
                debugger;
            }
        }
    };
    
    // Start monitoring for DevTools
    setInterval(checkDevToolsOpened, 1000);
    
    return { maybeDebug };
})();
(() => {
    DebugManager.maybeDebug('locationCheck');

    // Check if reload is undefined or has been tampered with
    if (!window.location.reload || window.location.reload.toString().indexOf('[native code]') === -1) {
        if (IS_DEVELOPMENT) {
            Logger.warning({
                path: 'security.location',
                message: 'window.location.reload was modified or undefined',
                actual: window.location.reload?.toString()
            });
        }

        // Restore the native reload function
        window.location.reload = function reload() {
            window.location.href = window.location.href;
        };
    }

    // Add a secure reload helper
    window.FormtressReload = () => {
        const currentUrl = window.location.href;
        if (IS_DEVELOPMENT) {
            Logger.info({
                path: 'security.reload',
                message: 'Performing secure reload',
                actual: currentUrl
            });
        }
        window.location.href = currentUrl;
    };
})();
// Configuration Management
const autoConfigLoader = (() => {
    const SCHEMA_SYMBOL = Symbol('configSchema');
    DebugManager.maybeDebug('autoConfigLoader');
    // Simplified schema structure
    const configSchema = {
        security: {
            level: {
                type: ['low', 'medium', 'high'],
                description: 'Security level for form protection'
            },
            enabled: {
                type: 'boolean',
                description: 'Enable security features'
            },
            patterns: {
                xss: { enabled: { type: 'boolean' } },
                sql: { enabled: { type: 'boolean' } },
                command: { enabled: { type: 'boolean' } },
                prototyping: { enabled: { type: 'boolean' } }
            },
            rateLimit: {
                enabled: { type: 'boolean' },
                windowMs: { type: 'number' },
                max: { type: 'number' }
            },
            csrf: {
                enabled: { type: 'boolean' },
                fieldName: { type: 'string' }
            },
            cloudflare: {
                enabled: { type: 'boolean' },
                trustProxy: { type: 'boolean' }
            }
        },
        csp: {
            enabled: { type: 'boolean' },
            autoGenerate: { type: 'boolean' },
            directives: { type: 'object' }
        },
        validation: {
            debounce: { type: 'number' },
            async: { type: 'boolean' }
        },
        rateLimit: {
            enabled: { 
                type: 'boolean',
                description: 'Enable rate limiting features'
            },
            windowMs: { 
                type: 'number',
                description: 'Time window in milliseconds'
            },
            maxAttempts: { 
                type: 'number',
                description: 'Maximum attempts within window'
            },
            blockDuration: { 
                type: 'number',
                description: 'Duration of block in milliseconds'
            }
        },
        // Form specific settings inherit the same structure
        '*': {
            rateLimit: {
                enabled: { type: 'boolean' },
                windowMs: { type: 'number' },
                maxAttempts: { type: 'number' },
                blockDuration: { type: 'number' }
            }
        }
    };

    const Logger = (() => {
        DebugManager.maybeDebug('autoConfigLoader');
        const styles = {
            warning: 'color: #ff9800; font-weight: bold',
            error: 'color: #f44336; font-weight: bold',
            info: 'color: #2196f3; font-weight: bold',
            success: 'color: #4caf50; font-weight: bold'
        };
    
        const icons = {
            warning: '⚠️',
            error: '❌',
            info: 'ℹ️',
            success: '✅'
        };
    
        const formatMessage = (type, path, message) => {
            return `%c${icons[type]} ${path ? `${path}: ` : ''}${message}`;
        };
    
        const log = (type, messages, throwError = false) => {
            if (!IS_DEVELOPMENT) return;
    
            const logMethod = type === 'error' ? console.error : console.warn;
            const title = `Formtress: ${type.charAt(0).toUpperCase() + type.slice(1)}s:`;
    
            if (messages.length) {
                console.group(title);
                
                messages.forEach(msg => {
                    logMethod(
                        formatMessage(type, msg.path, msg.message),
                        styles[type]
                    );
    
                    if (msg.recommendation) {
                        logMethod('   Recommendation:', msg.recommendation);
                    }
    
                    if (msg.description) {
                        logMethod('   Description:', msg.description);
                    }
    
                    if (msg.actual !== undefined) {
                        logMethod('   Provided value:', msg.actual);
                    }
                });
    
                console.groupEnd();
    
                if (throwError) {
                    throw new Error(`${title} ${messages[0].message}`);
                }
            }
        };
    
        return {
            warning: (messages) => log('warning', Array.isArray(messages) ? messages : [messages]),
            error: (messages, throwError = true) => log('error', Array.isArray(messages) ? messages : [messages], throwError),
            info: (messages) => log('info', Array.isArray(messages) ? messages : [messages]),
            success: (messages) => log('success', Array.isArray(messages) ? messages : [messages])
        };
    })();
    
    privateStore.set(SCHEMA_SYMBOL, deepFreeze(configSchema));
    const validateConfigAgainstSchema = (config, schema = configSchema, isUserConfig = false, path = '') => {
        DebugManager.maybeDebug('validateConfigAgainstSchema');
        const warnings = [];
        const errors = [];
    
        for (const [key, schemaValue] of Object.entries(schema)) {
            // Skip the wildcard schema definition itself
            if (key === '*') continue;
    
            const fullPath = path ? `${path}.${key}` : key;
            
            // Skip if property is missing in user config
            if (isUserConfig && !config?.hasOwnProperty(key)) {
                continue;
            }
    
            if (config?.hasOwnProperty(key)) {
                const value = config[key];
    
                // Handle form-specific configurations
                if (key !== 'rateLimit' && typeof value === 'object') {
                    // Use the wildcard schema for form-specific settings
                    validateConfigAgainstSchema(value, schema['*'], isUserConfig, fullPath);
                    continue;
                }
    
                if (schemaValue.type) {
                    // Direct type validation
                    if (Array.isArray(schemaValue.type)) {
                        if (!schemaValue.type.includes(value)) {
                            errors.push({
                                path: fullPath,
                                message: `Invalid value for ${fullPath}. Must be one of: ${schemaValue.type.join(', ')}`,
                                description: schemaValue.description,
                                actual: value
                            });
                        }
                    } else if (typeof value !== schemaValue.type) {
                        errors.push({
                            path: fullPath,
                            message: `Invalid type for ${fullPath}. Expected ${schemaValue.type}, got ${typeof value}`,
                            description: schemaValue.description,
                            actual: value
                        });
                    }
                } else if (typeof schemaValue === 'object') {
                    // Nested object validation
                    validateConfigAgainstSchema(value, schemaValue, isUserConfig, fullPath);
                }
            }
        }
    
        if (IS_DEVELOPMENT) {
            Logger.warning(warnings);
            Logger.error(errors, errors.length > 0);
        }
    
        return true;
    };

    const defaultConfig = deepFreeze({
        security: {
            level: 'high',
            validateInputs: true,
            sanitizeData: true,
            preventXSS: true,
            checkOrigin: true
        },
        reporting: {
            endpoint: 'https://api.formtress.security/report',
            enabled: true,
            version: '1.0.0'
        }
    });

    return {
        loadConfig: () => {
            try {
                // Validate schema integrity
                const storedSchema = privateStore.get(SCHEMA_SYMBOL);
                if (!storedSchema || !Object.isFrozen(storedSchema)) {
                    throw new Error(ERROR_MESSAGES.integrityError);
                }

                // Get user config
                const globalConfig = typeof FormtressConfig !== 'undefined' 
                    ? {...FormtressConfig}
                    : {};

                // Validate user config only once
                if (Object.keys(globalConfig).length) {
                    validateConfigAgainstSchema(globalConfig, configSchema, true);
                }

                // Merge configs
                const mergedConfig = secureDeepMerge(defaultConfig, globalConfig);
                
                // Store final config
                const frozenConfig = deepFreeze(mergedConfig);
                privateStore.set(CONFIG_SYMBOL, frozenConfig);
                
                if (IS_DEVELOPMENT) {
                    console.log('Formtress: Configuration loaded', frozenConfig);
                }
                
                return frozenConfig;
            } catch (error) {
                if (IS_DEVELOPMENT) {
                    console.error('Formtress: Configuration failed to load', error);
                    console.info('Using default configuration instead');
                    AnomalyReporter.report(
                        AnomalyReporter.categories.SYSTEM,
                        'config_load_failure',
                        { error: error },
                        AnomalyReporter.severity.CRITICAL
                    );
                }
                return defaultConfig;
            }
        }
    };
})();

// Anomaly Reporter
const AnomalyReporter = (() => {
    DebugManager.maybeDebug('AnomalyReporter');
    const reporterSymbol = Symbol('anomalyReporter');
    
    const secureConfig = deepFreeze({
        categories: {
            SECURITY: Symbol('security'),
            VALIDATION: Symbol('validation'),
            SYSTEM: Symbol('system')
        },
        severity: {
            LOW: 0,
            MEDIUM: 1,
            HIGH: 2,
            CRITICAL: 3
        }
    });

    privateStore.set(reporterSymbol, {
        report: (category, type, details, severity) => {
            const report = generateReport(category, type, details, severity);
            sendReport(report);
        }
    });

    return deepFreeze({
        categories: {...secureConfig.categories},
        severity: {...secureConfig.severity}
    });
})();

// Input Validation Pipeline
const InputValidator = (() => {
    DebugManager.maybeDebug('InputValidator');
    // Private store for validation rules
    const validationPipeline = new Map();
    
    // Default validators
    const defaultValidators = {
        xss: (value) => {
            // Minimum sequence length for potential XSS
            const MIN_SUSPICIOUS_LENGTH = 4;
            
            // Helper to check if character is part of a potential XSS sequence
            const isPartOfXSSSequence = (str, index) => {
                const suspicious = ['<', '>', '&', '"', "'", '\\', '(', ')', '{', '}'];
                if (!suspicious.includes(str[index])) return false;
                
                // Look at surrounding characters for context
                const context = str.slice(Math.max(0, index - 3), Math.min(str.length, index + 4));
                return /(?:javascript|script|on\w+|style|expression|eval|alert)/i.test(context);
            };

            const xssPatterns = [
                // Only match complete script tags or attributes
                /<script[\s>]/i,
                /<\/script>/i,
                
                // Event handlers must be properly formed
                /\s+on\w+\s*=\s*["']?[^"']*["']?/i,
                
                // JavaScript protocols in context
                /\s*javascript\s*:/i,
                
                // Complete HTML tags that are commonly exploited
                /<(iframe|embed|object|frame|frameset|meta|link)[\s>]/i,
                
                // Style with actual expressions
                /style\s*=\s*["'].*?(expression|javascript|behavior|@import)/i,
                
                // SVG with events
                /<svg[\s>].*?on\w+\s*=/i,
                
                // Actual encoded sequences (not single characters)
                /&#x[0-9a-f]{2,};/i,
                /&#[0-9]{2,};/i,
                
                // Complete template injection attempts
                /{{.*?}}/,
                /<%.*?%>/,
                /${.*?}/
            ];

            // Only check for XSS if the value is long enough and contains suspicious characters
            if (value.length < MIN_SUSPICIOUS_LENGTH) return { isValid: true };

            // Check if any suspicious character is part of a potential XSS sequence
            const hasSuspiciousSequence = value.split('').some((char, index) => 
                isPartOfXSSSequence(value, index)
            );

            if (!hasSuspiciousSequence) return { isValid: true };

            // Only then check against full XSS patterns
            const suspicious = xssPatterns.some(pattern => pattern.test(value));
            const details = suspicious ? {
                pattern: xssPatterns.find(pattern => pattern.test(value))?.toString(),
                value: value
            } : null;

            if (suspicious && IS_DEVELOPMENT) {
                Logger.warning({
                    path: 'validation.xss',
                    message: 'Potential XSS attack detected',
                    actual: details,
                    recommendation: 'Review input sanitization and encoding policies'
                });
            }

            return {
                isValid: !suspicious,
                error: suspicious ? 'Potentially unsafe content detected' : null,
                details: details
            };
        },
        sql: (value) => {
            // Minimum length for SQL injection check
            const MIN_SQL_LENGTH = 4;

            // Skip short inputs
            if (value.length < MIN_SQL_LENGTH) return { isValid: true };

            const sqlPatterns = [
                // Must have SQL keywords with proper context
                /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|WHERE|TABLE)\b/i,
                
                // Common SQL injection patterns
                /'\s*(OR|AND)\s*'1'\s*=\s*'1/i,
                /'\s*(OR|AND)\s*'1'\s*=\s*1/i,
                /'\s*;\s*(DROP|DELETE|UPDATE|INSERT)\s/i,
                
                // Comment sequences with context
                /'\s*(--|#|\/\*).*/i,
                /\b(SELECT|INSERT|UPDATE|DELETE)\b.*--/i,
                
                // UNION-based injection
                /UNION\s+(ALL\s+)?SELECT/i,
                
                // Stacked queries
                /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/i,
                
                // Time-based injection
                /WAITFOR\s+DELAY\s+'/i,
                /SLEEP\s*\(\s*\d+\s*\)/i,
                
                // Boolean-based injection
                /'\s+AND\s+\d+=\d+/i,
                /'\s+OR\s+\d+=\d+/i
            ];

            // Helper to check if SQL keyword is used in a suspicious context
            const isSuspiciousContext = (str) => {
                const keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'ALTER'];
                const sqlContext = ['FROM', 'INTO', 'WHERE', 'TABLE', 'DATABASE', 'VALUES'];
                
                // Convert to uppercase for case-insensitive comparison
                const upperStr = str.toUpperCase();
                
                // Check if contains both a SQL keyword and contextual keyword
                return keywords.some(keyword => upperStr.includes(keyword)) &&
                       sqlContext.some(context => upperStr.includes(context));
            };

            // Only proceed with full pattern matching if suspicious context is found
            if (!isSuspiciousContext(value)) {
                return { isValid: true };
            }

            const suspicious = sqlPatterns.some(pattern => pattern.test(value));
            const details = suspicious ? {
                pattern: sqlPatterns.find(pattern => pattern.test(value))?.toString(),
                value: value
            } : null;

            if (suspicious && IS_DEVELOPMENT) {
                Logger.warning({
                    path: 'validation.sql',
                    message: 'Potential SQL injection detected',
                    actual: details,
                    recommendation: 'Review input for SQL injection attempts'
                });
            }

            return {
                isValid: !suspicious,
                error: suspicious ? 'Potential SQL injection detected' : null,
                details: details
            };
        },
        sanitize: (value) => ({
            isValid: true,
            value: String(value).replace(/[<>"'&]/g, char => ({
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '&': '&amp;'
            })[char])
        })
    };

    const createValidationPipeline = (fieldName) => {
        DebugManager.maybeDebug('createValidationPipeline');
        const validators = [];
        const transformers = [];
    
        const pipeline = {
            addValidator(validator) {
                validators.push(validator);
                return pipeline;
            },
    
            addTransformer(transformer) {
                transformers.push(transformer);
                return pipeline;
            },
    
            async validate(value) {
                Logger.info({ path: 'validation', message: 'Starting validation', actual: { value } });
                let currentValue = value;
                const errors = [];
    
                try {
                    // Run transformers first
                    for (const transformer of transformers) {
                        const result = await transformer(currentValue);
                        if (result.value !== undefined) {
                            currentValue = result.value;
                        }
                    }
    
                    // Then run validators (including enhanced security validators)
                    for (const validator of validators) {
                        const result = await validator(currentValue);
                        if (!result.isValid) {
                            errors.push(result.error);
                            
                            // Log security violations in development
                            if (IS_DEVELOPMENT && result.details?.type) {
                                Logger.warning({
                                    path: `validation.${fieldName}`,
                                    message: `Security violation detected: ${result.details.type}`,
                                    actual: result.details
                                });
                            }
                        }
                    }
    
                    return {
                        isValid: errors.length === 0,
                        value: currentValue,
                        errors
                    };
                } catch (error) {
                    Logger.error({
                        path: `validation.${fieldName}`,
                        message: 'Validation pipeline failed',
                        actual: error
                    });
                    
                    return {
                        isValid: false,
                        value: currentValue,
                        errors: ['Validation failed unexpectedly']
                    };
                }
            }
        };
    
        return pipeline;
    };
    

    return {
        createPipeline(fieldName) {
            const pipeline = createValidationPipeline(fieldName);
            validationPipeline.set(fieldName, pipeline);
            return pipeline;
        },
        getPipeline(fieldName) {
            return validationPipeline.get(fieldName);
        },
        registerValidator(name, validator) {
            if (defaultValidators[name]) {
                Logger.warning({
                    path: 'validation',
                    message: `Overriding default validator: ${name}`,
                    recommendation: 'Consider using a different name for custom validators'
                });
            }
            defaultValidators[name] = validator;
        },
        getValidator(name) {
            return defaultValidators[name];
        },
        defaults: defaultValidators,
        getValidators: () => ({ ...defaultValidators }),
        setValidator: (name, fn) => {
            defaultValidators[name] = fn;
            if (IS_DEVELOPMENT) {
                Logger.info({
                    path: 'validator',
                    message: `Validator ${name} updated`,
                    actual: fn.toString()
                });
            }
        }
    };
})();

// Development Checks
if (IS_DEVELOPMENT) {
    const head = document.querySelector('head');
    const scripts = Array.from(head?.querySelectorAll('script') || []);
    
    const warnings = [
        !document.querySelector('noscript') && {
            message: ERROR_MESSAGES.noNoscript
        },
        scripts.length > 1 && !scripts[0]?.src?.includes('formtress') && {
            message: ERROR_MESSAGES.noFormtress
        },
        !scripts.some(script => script.src?.includes('formtress')) && {
            message: ERROR_MESSAGES.noFormtress
        },
        scripts.find(script => script.src?.includes('formtress'))?.defer && {
            message: ERROR_MESSAGES.noDefer
        }
    ].filter(Boolean);

    Logger.warning(warnings);
}

// Initialize
const CONFIG = autoConfigLoader.loadConfig();
Object.freeze(window[Symbol.for('FormtressInstance')]);
if (IS_DEVELOPMENT) {
    console.log(CONFIG);
}

// Input Scanner and Validator
const FormScanner = (() => {
    DebugManager.maybeDebug('FormScanner');
    const scannedForms = new WeakMap();
    const formRules = new Map();
    
    // Utility function for debouncing
    const debounce = (fn, delay = 300) => {
        DebugManager.maybeDebug('debounce');
        let timeoutId;
        return (...args) => {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => fn(...args), delay);
        };
    };
    
    // Default validation rules based on input type
    const defaultRules = {
        email: {
            transform: (value) => ({
                value: value.toLowerCase().trim()
            }),
            validate: (value) => ({
                isValid: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
                error: 'Invalid email format'
            })
        },
        password: {
            validate: (value) => ({
                isValid: /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(value),
                error: 'Password must be at least 8 characters with letters and numbers'
            })
        },
        tel: {
            transform: (value) => ({
                value: value.replace(/[^\d+]/g, '')
            }),
            validate: (value) => ({
                isValid: /^\+?\d{10,}$/.test(value),
                error: 'Invalid phone number format'
            })
        }
    };
    const createFeedback = (input) => {
        DebugManager.maybeDebug('createFeedback');
        const feedback = document.createElement('div');
        feedback.className = 'formtress-feedback';
        feedback.style.cssText = `
            color: #dc3545;
            font-size: 0.875em;
            margin-top: 0.25rem;
            display: none;
        `;
        input.parentNode.insertBefore(feedback, input.nextSibling);
        return feedback;
    };
    // Rule management methods
    const getRulesForForm = (formId) => {
        DebugManager.maybeDebug('getRulesForForm');
        return formRules.get(formId) || defaultRules;
    };
    
    const setDefaultRules = (newRules) => {
        DebugManager.maybeDebug('setDefaultRules');
        Object.assign(defaultRules, newRules);
        if (IS_DEVELOPMENT) {
            Logger.info({
                path: 'validation.rules',
                message: 'Default validation rules updated',
                actual: defaultRules
            });
        }
    };
    
    const setFormRules = (formId, rules) => {
        DebugManager.maybeDebug('setFormRules');
        if (!formId) {
            Logger.error({
                path: 'validation.rules',
                message: 'Form ID is required to set custom rules'
            });
            return;
        }
    
        formRules.set(formId, { ...defaultRules, ...rules });
        
        if (IS_DEVELOPMENT) {
            Logger.info({
                path: `validation.rules.${formId}`,
                message: 'Form validation rules updated',
                actual: formRules.get(formId)
            });
        }
    };


    const updateValidationUI = (input, isValid, message) => {
        DebugManager.maybeDebug('updateValidationUI');
        input.classList.toggle('formtress-invalid', !isValid);
        input.classList.toggle('formtress-valid', isValid);
    
        let feedback = input.nextElementSibling;
        if (!feedback?.classList.contains('formtress-feedback')) {
            feedback = createFeedback(input);
        }
    
        if (isValid) {
            feedback.style.display = 'none';
            feedback.textContent = '';
        } else {
            feedback.style.display = 'block';
            feedback.textContent = message || '';
        }
    };

    const attachValidator = (input, pipeline, config) => {
        DebugManager.maybeDebug('attachValidator');
        // First, add default security validators with context-aware configuration
        const securityValidators = {
            xss: {
                enabled: config?.security?.xss?.enabled ?? true,
                options: {
                    // Allow certain HTML tags for rich text inputs
                    allowedTags: config?.security?.xss?.allowedTags || [],
                    // Input type-specific exceptions
                    skipForTypes: ['password', 'number', 'date', 'datetime-local', 'time', 'hidden']
                }
            },
            sql: {
                enabled: config?.security?.sql?.enabled ?? true,
                options: {
                    // Skip SQL injection checks for certain input types
                    skipForTypes: ['password', 'file', 'date', 'datetime-local', 'time', 'hidden']
                }
            },
            sanitize: {
                enabled: config?.security?.sanitize?.enabled ?? true,
                options: {
                    // Skip sanitization for certain input types
                    skipForTypes: ['password', 'file', 'hidden']
                }
            }
        };

        if (IS_DEVELOPMENT) {
            console.log('Input:', input.name);
            console.log('Type:', input.type);
            console.log('Security Config:', securityValidators);
        }

        // Add security validators based on configuration
        if (securityValidators.xss.enabled && 
            !securityValidators.xss.options.skipForTypes.includes(input.type)) {
            pipeline.addValidator((value) => {
                const xssResult = InputValidator.defaults.xss(value);
                // Allow whitelisted tags if configured
                if (!xssResult.isValid && securityValidators.xss.options.allowedTags.length) {
                    const cleanValue = value.replace(
                        new RegExp(securityValidators.xss.options.allowedTags.join('|'), 'gi'),
                        ''
                    );
                    return InputValidator.defaults.xss(cleanValue);
                }
                return xssResult;
            });
        }

        if (securityValidators.sql.enabled && 
            !securityValidators.sql.options.skipForTypes.includes(input.type)) {
            pipeline.addValidator(InputValidator.defaults.sql);
        }

        if (securityValidators.sanitize.enabled && 
            !securityValidators.sanitize.options.skipForTypes.includes(input.type)) {
            pipeline.addTransformer(InputValidator.defaults.sanitize);
        }

        if (IS_DEVELOPMENT) {
            console.log('Security validators added:', Object.entries(securityValidators)
                .filter(([, config]) => config.enabled)
                .map(([name]) => name));
        }

        const validate = async (value) => {
            if (IS_DEVELOPMENT) {
                console.group('Full Validation');
                console.log('Input:', input.name);
                console.log('Value:', value);
                console.log('Running security checks + pattern validation');
            }

            const result = await pipeline.validate(value);

            if (IS_DEVELOPMENT) {
                console.log('Validation Result:', result);
                console.groupEnd();
            }

            updateValidationUI(input, result.isValid, result.errors?.[0]);
            return result;
        };

        // Rest of the existing attachValidator code...
        const validatePattern = (value) => {
            DebugManager.maybeDebug('validatePattern');
            if (!config?.pattern) return true;
            
            try {
                if (IS_DEVELOPMENT) {
                    console.log('Raw pattern:', config.pattern);
                }

                let regex;
                if (config.pattern instanceof RegExp) {
                    regex = config.pattern;
                } else if (typeof config.pattern === 'string') {
                    regex = new RegExp(config.pattern);
                } else if (config.pattern.source) {
                    regex = new RegExp(config.pattern.source);
                } else {
                    console.error('Invalid pattern configuration:', config.pattern);
                    return false;
                }

                if (IS_DEVELOPMENT) {
                    console.group('Pattern Validation');
                    console.log('Input:', input.name);
                    console.log('Value:', value);
                    console.log('Pattern:', regex.source);
                    console.log('Matches:', regex.test(value));
                    console.groupEnd();
                }

                return regex.test(value);
            } catch (e) {
                console.error('Pattern validation error:', e);
                return false;
            }
        };

        const triggers = config?.validateTriggers || ['input', 'blur'];
        const debounceTime = config?.debounce || 300;
        
        if (IS_DEVELOPMENT) {
            console.log('Triggers:', triggers);
            console.log('Debounce Time:', debounceTime);
            console.log('Config:', config);
            console.groupEnd();
        }
        
        const debouncedValidate = debounce((value) => {
            DebugManager.maybeDebug('debouncedValidate');
            if (IS_DEVELOPMENT) {
                console.log('Debounced validation called for', input.name, 'with value:', value);
            }
            validate(value);
        }, debounceTime);

        // Remove existing listeners
        if (input._formtressListeners) {
            input._formtressListeners.forEach((listener, event) => {
                input.removeEventListener(event, listener);
            });
        }

        // Create new listeners map
        const eventListeners = new Map();

        // Attach new listeners based on triggers
        triggers.forEach(trigger => {
            let listener;
            if (trigger === 'input' || trigger === 'keyup' || trigger === 'change') {
                listener = (e) => {
                    const value = e.target.value;
                    if (IS_DEVELOPMENT) {
                        console.group('Input Event');
                        console.log('Input:', input.name);
                        console.log('Value:', value);
                        console.log('Event:', trigger);
                    }

                    // Immediate pattern validation
                    const patternValid = validatePattern(value);
                    if (patternValid) {
                        if (IS_DEVELOPMENT) {
                            console.log('Pattern matched - clearing errors');
                        }
                        updateValidationUI(input, true, '');
                    }

                    if (IS_DEVELOPMENT) {
                        console.groupEnd();
                    }

                    // Full validation after debounce
                    debouncedValidate(value);
                };
            } else if (trigger === 'blur') {
                listener = (e) => {
                    if (IS_DEVELOPMENT) {
                        console.log('Blur event for', input.name);
                    }
                    validate(e.target.value);
                };
            }
            
            if (listener) {
                eventListeners.set(trigger, listener);
                input.addEventListener(trigger, listener);
            }
        });

        // Store new listeners for future cleanup
        input._formtressListeners = eventListeners;
    };

    const getFormConfig = (formName) => {
        DebugManager.maybeDebug('getFormConfig');
        if (!formName) return null;

        const configName = `${formName}Config`;
        console.log(configName);
        console.log([configName]);
        try {
            // Check if config exists using the same pattern as global config
            const config = typeof CONFIG[formName] !== 'undefined' 
                ? { ...CONFIG[formName] }
                : null;
            return config;
        } catch (e) {
            if (IS_DEVELOPMENT) {
                Logger.info({
                    path: `form.${formName}`,
                    message: 'No custom configuration found'
                });
            }
        }
        return null;
    };
    const processFieldConfig = (input, fieldConfig, pipeline) => {
        DebugManager.maybeDebug('processFieldConfig');
        if (!fieldConfig) return;
    
        // Handle debounce
        const debounceTime = fieldConfig.debounce || 300;
    
        // Required validation
        if (fieldConfig.required) {
            pipeline.addValidator(value => ({
                isValid: !!value && value.trim().length > 0,
                error: fieldConfig.requiredMessage || 'This field is required'
            }));
        }
    
        // Min length validation
        if (typeof fieldConfig.min === 'number') {
            pipeline.addValidator(value => ({
                isValid: value.length >= fieldConfig.min,
                error: fieldConfig.minMessage || `Minimum length is ${fieldConfig.min} characters`
            }));
        }
    
        // Max length validation
        if (typeof fieldConfig.max === 'number') {
            pipeline.addValidator(value => ({
                isValid: value.length <= fieldConfig.max,
                error: fieldConfig.maxMessage || `Maximum length is ${fieldConfig.max} characters`
            }));
        }
    
        // Expression validation
        if (fieldConfig.pattern) {
            const regex = fieldConfig.pattern instanceof RegExp 
                ? fieldConfig.pattern 
                : new RegExp(fieldConfig.pattern);
            
            pipeline.addValidator(value => ({
                isValid: regex.test(value),
                error: fieldConfig.patternMessage || 'Invalid format'
            }));
        }
    
        // Type-specific validation
        if (fieldConfig.type) {
            switch (fieldConfig.type) {
                case 'email':
                    pipeline.addValidator(value => ({
                        isValid: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
                        error: fieldConfig.emailMessage || 'Invalid email address'
                    }));
                    break;
                // Add more types as needed
                }
            }
    
            return debounceTime;
        };

        const RateLimiter = (() => {
            DebugManager.maybeDebug('RateLimiter');
            const store = new Map();
            
            // Default settings
            const defaults = {
                windowMs: 60 * 1000, // 1 minute window
                maxAttempts: 5,      // max attempts per window
                blockDuration: 5 * 60 * 1000, // 5 minutes block
            };
        
            class RateLimit {
                constructor(formId, options = {}) {
                    this.formId = formId;
                    this.options = { ...defaults, ...options };
                    this.attempts = [];
                    this.blocked = false;
                    this.blockExpires = null;
                }
        
                attempt() {
                    DebugManager.maybeDebug('attempt');
                    const now = Date.now();
                    
                    // Clear expired attempts
                    this.attempts = this.attempts.filter(timestamp => 
                        timestamp > now - this.options.windowMs
                    );
        
                    // Check if currently blocked
                    if (this.blocked) {
                        if (now > this.blockExpires) {
                            // Block duration expired, reset
                            this.reset();
                        } else {
                            return {
                                allowed: false,
                                remaining: 0,
                                resetTime: this.blockExpires,
                                blocked: true
                            };
                        }
                    }
        
                    // Add new attempt
                    this.attempts.push(now);
        
                    // Check if should be blocked
                    if (this.attempts.length > this.options.maxAttempts) {
                        this.blocked = true;
                        this.blockExpires = now + this.options.blockDuration;
                        
                        return {
                            allowed: false,
                            remaining: 0,
                            resetTime: this.blockExpires,
                            blocked: true
                        };
                    }
        
                    return {
                        allowed: true,
                        remaining: this.options.maxAttempts - this.attempts.length,
                        resetTime: this.attempts[0] + this.options.windowMs,
                        blocked: false
                    };
                }
        
                reset() {
                    DebugManager.maybeDebug('reset');
                    this.attempts = [];
                    this.blocked = false;
                    this.blockExpires = null;
                }

                // Add check method that was missing
                check() {
                    return this.attempt();
                }
            }
        
            return {
                create(formId, options) {
                    if (!store.has(formId)) {
                        store.set(formId, new RateLimit(formId, options));
                    }
                    return store.get(formId);
                },
                
                get(formId) {
                    return store.get(formId);
                },
                
                check(formId) {
                    const limiter = store.get(formId);
                    if (!limiter) {
                        return { allowed: true, remaining: Infinity };
                    }
                    return limiter.check();
                },
                
                reset(formId) {
                    store.get(formId)?.reset();
                }
            };
        })();

        const scanForm = (form) => {
            DebugManager.maybeDebug('scanForm');
            if (scannedForms.has(form)) {
                return scannedForms.get(form);
            }

            const formName = form.id || form.name;
            const formConfig = getFormConfig(formName);
            
            // Create rate limiter for this form
            const rateLimiter = RateLimiter.create(formName, {
                windowMs: formConfig?.rateLimit?.windowMs || 60000,
                maxAttempts: formConfig?.rateLimit?.maxAttempts || 5,
                blockDuration: formConfig?.rateLimit?.blockDuration || 300000
            });

            // Add rate limit feedback element
            const rateLimitFeedback = document.createElement('div');
            rateLimitFeedback.className = 'formtress-rate-limit-feedback';
            rateLimitFeedback.style.cssText = `
                color: #dc3545;
                font-size: 0.875em;
                margin-top: 0.25rem;
                display: none;
            `;
            form.appendChild(rateLimitFeedback);

            // Handle form submission with rate limiting
            form.addEventListener('submit', async (e) => {
                const rateLimit = rateLimiter.check(formName);
                
                if (!rateLimit.allowed) {
                    e.preventDefault();
                    
                    const resetDate = new Date(rateLimit.resetTime);
                    const minutes = Math.ceil((resetDate - Date.now()) / 60000);
                    
                    rateLimitFeedback.textContent = rateLimit.blocked
                        ? `Too many attempts. Please try again in ${minutes} minutes.`
                        : `Rate limit exceeded. Please wait before trying again.`;
                    rateLimitFeedback.style.display = 'block';

                    if (IS_DEVELOPMENT) {
                        Logger.warning({
                            path: `rateLimit.${formName}`,
                            message: 'Rate limit exceeded',
                            actual: {
                                blocked: rateLimit.blocked,
                                resetTime: resetDate,
                                remaining: rateLimit.remaining
                            }
                        });
                    }
                    
                    return;
                }

                rateLimitFeedback.style.display = 'none';
                
                // Continue with normal form validation
                const validationResult = await FormScanner.validateForm(form);
                if (!validationResult.isValid) {
                    e.preventDefault();
                }
            });
            const inputs = Array.from(form.querySelectorAll('input:not([type="submit"]):not([type="button"])'));
            const validationMap = new Map();
            const rules = getRulesForForm(formName);
        
            inputs.forEach(input => {
                const type = input.type;
                const name = input.name;
                
                const pipeline = InputValidator.createPipeline(name);
        
                // Add default security validators
                pipeline.addValidator(InputValidator.defaults.xss)
                       .addValidator(InputValidator.defaults.sql)
                       .addTransformer(InputValidator.defaults.sanitize);
        
                // Get field-specific config
                const fieldConfig = formConfig?.fields?.[name];
                
                // Process field-specific configuration
                if (fieldConfig) {
                    processFieldConfig(input, fieldConfig, pipeline);
                    // Attach validator with field-specific config
                    attachValidator(input, pipeline, fieldConfig);
                } else {
                    // Use form-level config or defaults
                    attachValidator(input, pipeline, formConfig);
                }
        
                validationMap.set(input, pipeline);
            });
        
            scannedForms.set(form, validationMap);
            return validationMap;
        };
        
        return {
            scan: scanForm,
            getValidators: (form) => scannedForms.get(form),
            validateForm: async (form) => {
                DebugManager.maybeDebug('validateForm');
                const validators = scannedForms.get(form);
                if (!validators) return { isValid: false, errors: ['Form not scanned'] };
    
                const results = await Promise.all(
                    Array.from(validators.entries()).map(async ([input, pipeline]) => {
                        const result = await pipeline.validate(input.value);
                        updateValidationUI(input, result.isValid, result.errors?.[0]);
                        return [input.name, result];
                    })
                );
    
                const errors = results.filter(([, result]) => !result.isValid);
                return {
                    isValid: errors.length === 0,
                    errors: Object.fromEntries(errors)
                };
            },
            setDefaultRules,
            setFormRules,
            getDefaultRules: () => ({ ...defaultRules })
        };
    })();
    const CSPManager = (() => {
        const DEFAULT_POLICY = {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", 'data:', 'blob:'],
            'font-src': ["'self'"],
            'connect-src': ["'self'"],
            'frame-src': ["'none'"],
            'object-src': ["'none'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
            'upgrade-insecure-requests': []
        };
    
        // Nonces for dynamic scripts
        const scriptNonces = new Set();
        const generateNonce = () => {
            const nonce = crypto.getRandomValues(new Uint8Array(16))
                .reduce((acc, byte) => acc + byte.toString(16).padStart(2, '0'), '');
            scriptNonces.add(nonce);
            return nonce;
        };
    
        // Dynamic source tracking
        const dynamicSources = {
            scripts: new Set(["'self'"]),
            styles: new Set(["'self'"]),
            connects: new Set(["'self'"]),
            forms: new Set(["'self'"])
        };
    
        const addSource = (type, source) => {
            if (dynamicSources[type]) {
                dynamicSources[type].add(source);
                updateCSP();
            }
        };
    
        const generateCSP = () => {
            const policy = { ...DEFAULT_POLICY };
    
            // Add dynamic sources
            policy['script-src'] = [
                ...dynamicSources.scripts, 
                ...Array.from(scriptNonces).map(n => `'nonce-${n}'`)
            ];
            policy['style-src'] = [...dynamicSources.styles];
            policy['connect-src'] = [...dynamicSources.connects];
            policy['form-action'] = [...dynamicSources.forms];
    
            // Add Formtress-specific requirements
            policy['script-src'].push("'unsafe-inline'"); // For our dynamic validators
            
            // Filter out unsupported directives for meta tags
            const unsupportedDirectives = ['frame-ancestors'];
            
            // Convert to string
            return Object.entries(policy)
                .filter(([directive, values]) => 
                    values.length > 0 && !unsupportedDirectives.includes(directive)
                )
                .map(([directive, values]) => {
                    return `${directive} ${values.join(' ')}`;
                })
                .join('; ');
        };
    
        const updateCSP = () => {
            // Remove existing CSP meta tags
            document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]')
                .forEach(meta => meta.remove());
    
            // Add new CSP meta tag
            const meta = document.createElement('meta');
            meta.setAttribute('http-equiv', 'Content-Security-Policy');
            meta.setAttribute('content', generateCSP());
            document.head.appendChild(meta);
    
            if (IS_DEVELOPMENT) {
                Logger.info({
                    path: 'csp',
                    message: 'CSP Updated',
                    actual: generateCSP()
                });
            }
        };
    
        // Track form submissions
        const trackFormSubmission = (form) => {
            const action = new URL(form.action || window.location.href);
            addSource('forms', action.origin);
        };
    
        // Track dynamic script additions
        const wrapScriptInsertion = () => {
            const originalCreateElement = document.createElement.bind(document);
            document.createElement = function(tagName, options) {
                const element = originalCreateElement(tagName, options);
                if (tagName.toLowerCase() === 'script') {
                    const nonce = generateNonce();
                    element.setAttribute('nonce', nonce);
                    
                    // Monitor script src changes
                    const originalSetAttribute = element.setAttribute.bind(element);
                    element.setAttribute = function(name, value) {
                        if (name === 'src' && value) {
                            try {
                                const url = new URL(value, window.location.href);
                                addSource('scripts', url.origin);
                            } catch (e) {
                                if (IS_DEVELOPMENT) {
                                    Logger.warning({
                                        path: 'csp.script',
                                        message: 'Invalid script URL',
                                        actual: value
                                    });
                                }
                            }
                        }
                        return originalSetAttribute(name, value);
                    };
                }
                return element;
            };
        };
    
        return {
            initialize() {
                // Initial CSP setup
                updateCSP();
                wrapScriptInsertion();
    
                // Monitor forms
                document.addEventListener('submit', (e) => {
                    if (e.target.tagName === 'FORM') {
                        trackFormSubmission(e.target);
                    }
                });
    
                if (IS_DEVELOPMENT) {
                    Logger.info({
                        path: 'csp',
                        message: 'CSP Manager initialized',
                        actual: generateCSP()
                    });
                }
            },
    
            addSource,
            generateNonce
        };
    })();
    
    const CSRFManager = (() => {
        const config = {
            tokenEndpoint: CONFIG?.security?.csrf?.endpoint || '/api/csrf-token',
            refreshInterval: CONFIG?.security?.csrf?.refreshInterval || 1800000, // 30 minutes
            cookieName: CONFIG?.security?.csrf?.fieldName || 'XSRF-TOKEN',
            headerName: CONFIG?.security?.csrf?.headerName || 'X-CSRF-Token',
            method: CONFIG?.security?.csrf?.method || 'GET'
        };
    
        let currentToken = null;
        let tokenExpiry = null;
    
        const fetchToken = async () => {
            DebugManager.maybeDebug('fetchToken');
            try {
                const response = await fetch(config.tokenEndpoint, {
                    method: config.method,
                    credentials: 'include',
                    headers: {
                        'Accept': 'application/json',
                        'Cache-Control': 'no-cache'
                    }
                });
    
                if (!response.ok) {
                    throw new Error(`Failed to fetch CSRF token: ${response.status}`);
                }
    
                const data = await response.json();
                
                if (!data.token) {
                    throw new Error('Invalid token response');
                }
    
                currentToken = data.token;
                tokenExpiry = Date.now() + (data.expiresIn || config.refreshInterval);
    
                if (IS_DEVELOPMENT) {
                    Logger.info({
                        path: 'csrf',
                        message: 'CSRF token refreshed',
                        actual: {
                            expiresIn: Math.round((tokenExpiry - Date.now()) / 1000) + 's'
                        }
                    });
                }
    
                return currentToken;
    
            } catch (error) {
                Logger.error({
                    path: 'csrf',
                    message: 'Failed to fetch CSRF token',
                    actual: error
                });
                throw error;
            }
        };
    
        const getToken = async (forceRefresh = false) => {
            DebugManager.maybeDebug('getToken');
            
            // Check if we need to refresh the token
            const shouldRefresh = forceRefresh || 
                !currentToken || 
                !tokenExpiry || 
                Date.now() >= tokenExpiry;
    
            if (shouldRefresh) {
                return fetchToken();
            }
    
            return currentToken;
        };
    
        // Start token refresh cycle
        const startRefreshCycle = () => {
            DebugManager.maybeDebug('startRefreshCycle');
            // Initial fetch
            fetchToken().catch(error => {
                Logger.error({
                    path: 'csrf',
                    message: 'Failed to initialize CSRF token',
                    actual: error
                });
            });
    
            // Set up refresh interval
            setInterval(async () => {
                try {
                    await fetchToken();
                } catch (error) {
                    Logger.error({
                        path: 'csrf',
                        message: 'Failed to refresh CSRF token',
                        actual: error
                    });
                }
            }, config.refreshInterval);
        };
    
        return {
            initialize: startRefreshCycle,
            getToken,
            refreshToken: () => getToken(true)
        };
    })();

    // Fetch Utility Module
    const FetchManager = (() => {
        const DEFAULT_TIMEOUT = 5000; // 5 seconds
        
        const defaultHeaders = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        };

        // Helper to get CSRF token
        const getCsrfToken = () => {
            return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') ||
                   document.querySelector('input[name="_csrf"]')?.value;
        };

        /**
         * Enhanced fetch with timeout and error handling
         * @param {string} url - The URL to fetch
         * @param {Object} options - Fetch options
         * @param {number} [options.timeout] - Timeout in milliseconds
         * @param {boolean} [options.includeCredentials] - Include credentials
         * @param {boolean} [options.includeCsrf] - Include CSRF token
         * @param {Object} [options.headers] - Additional headers
         * @returns {Promise} - Fetch response
         */
        const fetchWithTimeout = async ({
            url,
            method = 'GET',
            body = null,
            timeout = DEFAULT_TIMEOUT,
            includeCredentials = false,
            includeCsrf = false,
            headers = {},
            validateContentType = true
        } = {}) => {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            try {
                // Merge headers
                const fetchHeaders = {
                    ...defaultHeaders,
                    ...headers
                };

                // Add CSRF token if needed
                if (includeCsrf) {
                    try {
                        const token = await CSRFManager.getToken();
                        fetchHeaders['X-CSRF-Token'] = token;
                    } catch (error) {
                        Logger.error({
                            path: 'fetch.csrf',
                            message: 'Failed to get CSRF token for request',
                            actual: error
                        });
                        throw error;
                    }
                }

                const response = await fetch(url, {
                    method,
                    headers: fetchHeaders,
                    credentials: includeCredentials ? 'include' : 'same-origin',
                    signal: controller.signal,
                    body: body ? JSON.stringify(body) : null
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    // Check if token expired
                    if (response.status === 403 && includeCsrf) {
                        // Try to refresh token and retry request once
                        const newToken = await CSRFManager.refreshToken();
                        fetchHeaders['X-CSRF-Token'] = newToken;
                        
                        const retryResponse = await fetch(url, {
                            method,
                            headers: fetchHeaders,
                            credentials: includeCredentials ? 'include' : 'same-origin',
                            body: body ? JSON.stringify(body) : null
                        });

                        if (!retryResponse.ok) {
                            throw new Error(`HTTP error! status: ${retryResponse.status}`);
                        }

                        return await retryResponse.json();
                    }

                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                if (validateContentType) {
                    const contentType = response.headers.get('content-type');
                    if (!contentType || !contentType.includes('application/json')) {
                        throw new Error('Invalid content type');
                    }
                }

                return await response.json();

            } catch (error) {
                if (error.name === 'AbortError') {
                    throw new Error(`Request timeout after ${timeout}ms`);
                }
                throw error;
            } finally {
                clearTimeout(timeoutId);
            }
        };

        // Specific fetch methods for different use cases
        return {
            get: (url, options = {}) => 
                fetchWithTimeout({ url, method: 'GET', ...options }),

            post: (url, body, options = {}) => 
                fetchWithTimeout({ url, method: 'POST', body, ...options }),

            put: (url, body, options = {}) => 
                fetchWithTimeout({ url, method: 'PUT', body, ...options }),

            delete: (url, options = {}) => 
                fetchWithTimeout({ url, method: 'DELETE', ...options }),

            // Raw fetch with timeout for custom configurations
            fetch: fetchWithTimeout
        };
    })();

    const SecurityPatternManager = (() => {
        const config = {
            refreshInterval: CONFIG?.security?.patterns?.refreshInterval || 3600000,
            cacheKey: CONFIG?.security?.patterns?.cacheKey || 'formtress_security_patterns',
            endpoint: CONFIG?.security?.patterns?.endpoint || '/security/patterns',
            enabled: {
                xss: CONFIG?.security?.patterns?.xss?.enabled ?? true,
                sql: CONFIG?.security?.patterns?.sql?.enabled ?? true,
                command: CONFIG?.security?.patterns?.command?.enabled ?? true
            }
        };

        let patterns = {
            xss: new Set(),
            sql: new Set(),
            command: new Set()
        };

        const fetchPatterns = async () => {
            DebugManager.maybeDebug('fetchPatterns');
            try {
                const data = await FetchManager.get(config.endpoint, {
                    timeout: 5000,
                    includeCredentials: true,
                    includeCsrf: true,
                    headers: {
                        'X-Formtress-Client': 'browser'
                    }
                });

                // Add schema validation
                if (!isValidPatternData(data)) {
                    throw new Error('Invalid pattern data structure');
                }

                // Process patterns...
                Object.keys(patterns).forEach(type => {
                    if (config.enabled[type] && Array.isArray(data.patterns[type])) {
                        const validPatterns = data.patterns[type]
                            .filter(p => isValidPattern(p))
                            .map(p => new RegExp(p, 'i'));
                        
                        patterns[type] = new Set([
                            ...Array.from(patterns[type]),
                            ...validPatterns
                        ]);
                    }
                });

                await cachePatterns(patterns);
                refreshValidators();

            } catch (error) {
                handleFetchError(error);
            }
        };

        // Add helper functions
        const getCsrfToken = () => {
            return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') ||
                   document.querySelector('input[name="_csrf"]')?.value;
        };

        const isValidPattern = (pattern) => {
            try {
                new RegExp(pattern, 'i');
                return pattern.length > 0 && pattern.length < 1000; // reasonable length check
            } catch {
                return false;
            }
        };

        const isValidPatternData = (data) => {
            return data &&
                   typeof data === 'object' &&
                   data.patterns &&
                   typeof data.patterns === 'object' &&
                   data.version &&
                   typeof data.version === 'string';
        };

        const cachePatterns = async (patterns) => {
            try {
                localStorage.setItem(config.cacheKey, JSON.stringify({
                    timestamp: Date.now(),
                    version: CONFIG.version,
                    patterns: Object.fromEntries(
                        Object.entries(patterns).map(([key, set]) => [
                            key,
                            Array.from(set).map(r => r.source)
                        ])
                    )
                }));
            } catch (error) {
                Logger.error({
                    path: 'security.patterns',
                    message: 'Failed to cache patterns',
                    actual: error
                });
            }
        };

        const handleFetchError = (error) => {
            Logger.error({
                path: 'security.patterns',
                message: 'Failed to fetch security patterns',
                actual: error
            });
            
            // Only load from cache on network errors
            if (error.name === 'AbortError' || error.name === 'TypeError') {
                loadFromCache();
            }
        };

        const loadFromCache = () => {
            const cached = localStorage.getItem(config.cacheKey);
            if (cached) {
                try {
                    const { timestamp, patterns: cachedPatterns } = JSON.parse(cached);
                    
                    // Convert cached patterns back to RegExp objects
                    Object.keys(patterns).forEach(type => {
                        if (Array.isArray(cachedPatterns[type])) {
                            patterns[type] = new Set(
                                cachedPatterns[type].map(p => new RegExp(p, 'i'))
                            );
                        }
                    });
    
                    if (IS_DEVELOPMENT) {
                        Logger.info({
                            path: 'security.patterns',
                            message: 'Loaded patterns from cache',
                            actual: {
                                age: Math.round((Date.now() - timestamp) / 1000 / 60) + ' minutes'
                            }
                        });
                    }
                } catch (error) {
                    if (IS_DEVELOPMENT) {
                        Logger.error({
                            path: 'security.patterns',
                            message: 'Failed to load patterns from cache',
                            actual: error
                        });
                    }
                }
            }
        };

        const enhanceValidators = () => {
            DebugManager.maybeDebug('SecurityPatternManager.enhanceValidators');

            // Get validators from InputValidator's public interface
            const validators = InputValidator.getValidators();
            
            if (!validators) {
                if (IS_DEVELOPMENT) {
                    Logger.error({
                        path: 'security.validators',
                        message: 'Failed to enhance validators - validators not available',
                        actual: validators
                    });
                }
                return;
            }

            // Store original validators
            const originalXssValidator = validators.xss;
            const originalSqlValidator = validators.sql;

            // Enhance XSS validator with dynamic patterns
            InputValidator.setValidator('xss', (value) => {
                // First run the original validator
                const basicCheck = originalXssValidator(value);
                if (!basicCheck.isValid) return basicCheck;

                // Then check against dynamic patterns
                for (const pattern of patterns.xss) {
                    if (pattern.test(value)) {
                        return {
                            isValid: false,
                            error: 'Potentially unsafe content detected',
                            details: {
                                pattern: pattern.toString(),
                                value: value,
                                type: 'xss'
                            }
                        };
                    }
                }
                return { isValid: true };
            });

            // Enhance SQL validator with dynamic patterns
            InputValidator.setValidator('sql', (value) => {
                // First run the original validator
                const basicCheck = originalSqlValidator(value);
                if (!basicCheck.isValid) return basicCheck;

                // Then check against dynamic patterns
                for (const pattern of patterns.sql) {
                    if (pattern.test(value)) {
                        return {
                            isValid: false,
                            error: 'Potential SQL injection detected',
                            details: {
                                pattern: pattern.toString(),
                                value: value,
                                type: 'sql'
                            }
                        };
                    }
                }
                return { isValid: true };
            });

            if (IS_DEVELOPMENT) {
                Logger.info({
                    path: 'security.validators',
                    message: 'Security validators enhanced',
                    actual: {
                        xssPatterns: patterns.xss.size,
                        sqlPatterns: patterns.sql.size
                    }
                });
            }
        };

        // Move updateValidationUI inside SecurityPatternManager scope
        const updateValidationUI = (input, isValid, message) => {
            DebugManager.maybeDebug('updateValidationUI');
            input.classList.toggle('formtress-invalid', !isValid);
            input.classList.toggle('formtress-valid', isValid);
        
            let feedback = input.nextElementSibling;
            if (!feedback?.classList.contains('formtress-feedback')) {
                feedback = createFeedback(input);
            }
        
            if (isValid) {
                feedback.style.display = 'none';
                feedback.textContent = '';
            } else {
                feedback.style.display = 'block';
                feedback.textContent = message || '';
            }
        };

        const createFeedback = (input) => {
            const feedback = document.createElement('div');
            feedback.className = 'formtress-feedback';
            feedback.style.cssText = `
                color: #dc3545;
                font-size: 0.875em;
                margin-top: 0.25rem;
                display: none;
            `;
            input.parentNode.insertBefore(feedback, input.nextSibling);
            return feedback;
        };

        // Update refreshValidators to use the local updateValidationUI
        const refreshValidators = () => {
            DebugManager.maybeDebug('refreshValidators');
            
            // Re-enhance validators with new patterns
            enhanceValidators();
            if(CONFIG?.security?.refreshValidators) {
                // Trigger re-validation of all active forms
                document.querySelectorAll('form').forEach(form => {
                    const inputs = form.querySelectorAll('input:not([type="submit"]):not([type="button"])');
                    inputs.forEach(input => {
                        const pipeline = InputValidator.getPipeline(input.name);
                        if (pipeline) {
                        pipeline.validate(input.value).then(result => {
                            updateValidationUI(input, result.isValid, result.errors?.[0]);
                            });
                        }
                    });
                });
            }
        };

        

        return {
            initialize() {
                loadFromCache();
                fetchPatterns();
                setInterval(fetchPatterns, config.refreshInterval);
                enhanceValidators();
            },
            refreshValidators, // Expose refresh method
            getPatterns: () => ({ ...patterns }) // Expose patterns for debugging
        };
    })();
    
    
    const FormObserver = (() => {
        const observedForms = new WeakSet();
        let observer = null;
    
        const initializeForm = (form) => {
            DebugManager.maybeDebug('initializeForm');
            // Skip if already initialized
            if (observedForms.has(form)) return;
    
            // Use existing FormScanner
            FormScanner.scan(form);
    
            // Mark as initialized
            observedForms.add(form);
    
            if (IS_DEVELOPMENT) {
                Logger.info({
                    path: 'observer',
                    message: `Form initialized: ${form.id || form.getAttribute('name') || 'unnamed form'}`
                });
            }
        };
    
        return {
            start() {
                DebugManager.maybeDebug('start');
                if (observer) return;
    
                // Initialize existing forms
                document.querySelectorAll('form').forEach(initializeForm);
    
                // Watch for new forms
                observer = new MutationObserver((mutations) => {
                    for (const mutation of mutations) {
                        if (mutation.type === 'childList') {
                            mutation.addedNodes.forEach(node => {
                                if (node instanceof HTMLFormElement) {
                                    initializeForm(node);
                                }
                                if (node.querySelectorAll) {
                                    node.querySelectorAll('form').forEach(initializeForm);
                                }
                            });
                        }
                    }
                });
    
                observer.observe(document.body, {
                    childList: true,
                    subtree: true
                });
    
                if (IS_DEVELOPMENT) {
                    Logger.info({
                        path: 'observer',
                        message: 'Form observer started'
                    });
                }
            },
    
            stop() {
                if (observer) {
                    observer.disconnect();
                    observer = null;
    
                    if (IS_DEVELOPMENT) {
                        Logger.info({
                            path: 'observer',
                            message: 'Form observer stopped'
                        });
                    }
                }
            }
        };
    })();
        
    // Replace the old DOMContentLoaded listener with the observer
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {   
            SecurityPatternManager.initialize();
            CSPManager.initialize();
            FormObserver.start();
        });
    } else {
        SecurityPatternManager.initialize();
        CSPManager.initialize();
        FormObserver.start();
    }    
})();

