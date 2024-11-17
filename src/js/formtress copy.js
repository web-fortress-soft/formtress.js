/**
 * Formtress.js - Enterprise Banking-Grade Form Security Library
 * Version: 1.0.0
 */
(() => {

    const IS_DEVELOPMENT = /^(localhost|127\.0\.0\.192\.168\.)|(:[0-9]{4})/i.test(window.location.host);
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

    // Configuration Management
    const autoConfigLoader = (() => {
        const SCHEMA_SYMBOL = Symbol('configSchema');
        
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
            }
        };

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
            const warnings = [];
            const errors = [];

            for (const [key, schemaValue] of Object.entries(schema)) {
                const fullPath = path ? `${path}.${key}` : key;
                
                // Skip if property is missing in user config
                if (isUserConfig && !config?.hasOwnProperty(key)) {
                    continue;
                }

                if (config?.hasOwnProperty(key)) {
                    const value = config[key];

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

                    // Security warnings
                    if (fullPath === 'security.level' && value === 'low') {
                        warnings.push({
                            path: fullPath,
                            message: 'Low security level may expose your forms to attacks',
                            recommendation: 'Consider using "medium" or "high" security level'
                        });
                    }
                    if (fullPath === 'security.csrf.enabled' && value === false) {
                        warnings.push({
                            path: fullPath,
                            message: 'CSRF protection is disabled',
                            recommendation: 'Enable CSRF protection for better security'
                        });
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
        // Private store for validation rules
        const validationPipeline = new Map();
        
        // Default validators
        const defaultValidators = {
            xss: (value) => {
                const xssPatterns = [
                    // Script tags and attributes
                    /<script[^>]*>[\s\S]*?<\/script>/i,
                    /<script[^>]*>/i,
                    
                    // Event handlers
                    /\bon\w+\s*=[\s\S]*?(?:"|')/i,
                    
                    // JavaScript protocols
                    /javascript:|data:|vbscript:|livescript:/i,
                    
                    // Base64 encoded JavaScript
                    /base64[^<]*/i,
                    
                    // Expression binding
                    /expression\s*\([^)]*\)/i,
                    
                    // Meta characters
                    /-moz-binding[\s\S]*?:/i,
                    
                    // Common HTML element injection
                    /<iframe[^>]*>/i,
                    /<embed[^>]*>/i,
                    /<object[^>]*>/i,
                    
                    // Style with expressions
                    /style\s*=[\s\S]*?(expression|behavior|javascript|vbscript)[\s\S]*?["']/i,
                    
                    // SVG script content
                    /<svg[\s\S]*?on\w+[\s\S]*?>/i,
                    
                    // Malicious URL parameters
                    /src[\s\S]*?=[\s\S]*?(javascript|data):/i,
                    
                    // Import statements
                    /@import\s+['"]*data:text\/html/i,
                    
                    // HTML comments containing scripts
                    /<!--[\s\S]*?-->/i,
                    
                    // Encoded characters that might be used to bypass filters
                    /&#x([0-9a-f]{2});/i,
                    /&#([0-9]{2,3});/i,
                    
                    // Unicode escapes
                    /\\u([0-9a-f]{4})/i,
                    
                    // Null bytes
                    /\x00/,
                    
                    // DOM-based XSS patterns
                    /\.\s*innerHTML\s*=/i,
                    /\.\s*outerHTML\s*=/i,
                    /document\s*\.\s*write/i,
                    /document\s*\.\s*writeln/i
                ];

                const suspicious = xssPatterns.some(pattern => pattern.test(value));
                const details = suspicious ? {
                    pattern: xssPatterns.find(pattern => pattern.test(value))?.toString(),
                    value: value
                } : null;

                if (suspicious && IS_DEVELOPMENT) {
                    Logger.warning({
                        path: 'validation.xss',
                        message: 'Potential XSS attack detected',
                        actual: details
                    });
                }

                return {
                    isValid: !suspicious,
                    error: suspicious ? 'Potentially unsafe content detected' : null,
                    details: details
                };
            },
            sql: (value) => {
                const suspicious = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)|(-{2}|;)/i.test(value);
                return {
                    isValid: !suspicious,
                    error: suspicious ? 'Potential SQL injection detected' : null
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
        
                        // Then run validators
                        let isValid = true;
                        for (const validator of validators) {
                            const result = await validator(currentValue);
                            if (!result.isValid) {
                                isValid = false;
                                errors.push(result.error);
                            }
                        }
        
                        return {
                            isValid,
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
            defaults: defaultValidators
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
        const scannedForms = new WeakMap();
        const formRules = new Map();
        
        // Utility function for debouncing
        const debounce = (fn, delay = 300) => {
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
            return formRules.get(formId) || defaultRules;
        };
    
        const setDefaultRules = (newRules) => {
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
                console.group('Security Validators Setup');
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
                    .map(([name]) => name)
                );
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
                if (trigger === 'input') {
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
        const scanForm = (form) => {
            if (scannedForms.has(form)) {
                return scannedForms.get(form);
            }
        
            const formName = form.id || form.name;
            const formConfig = getFormConfig(formName);
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
    document.addEventListener('DOMContentLoaded', () => {
        //query all forms
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            FormScanner.scan(form);
        })
    })
        // Usage example:
        if (IS_DEVELOPMENT) {
        document.addEventListener('DOMContentLoaded', () => {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                FormScanner.scan(form);
                
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const result = await FormScanner.validateForm(form);
                    
                    if (result.isValid) {
                        Logger.success({
                            path: `form.${form.id || 'unknown'}`,
                            message: 'Form validation successful'
                        });
                    } else {
                        Logger.error({
                            path: `form.${form.id || 'unknown'}`,
                            message: 'Form validation failed',
                            actual: result.errors
                        });
                    }
                });
            });
        });
    }
})();

