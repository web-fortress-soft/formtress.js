/**
 * Formtress.js - Enterprise Banking-Grade Form Security Library
 * Because security starts with the form.
 * @author: Resti Guay
 * Version: 0.1.0
 * Features:
 * - Bank-grade form protection and validation
 * - Real-time threat detection and prevention
 * - Multi-layer security architecture:
 *   - XSS, SQL Injection, CSRF Protection
 *   - Input sanitization and validation
 *   - Rate limiting and brute force prevention
 *   - Tampering detection
 *   - DevTools monitoring
 *   - Browser fingerprinting
 *   - DOM manipulation protection
 * - Compliance ready (PCI DSS, GDPR, CCPA)
 * - Automated security hardening
 * - Continuous security monitoring
 * - Audit logging and reporting
 * - Zero-trust architecture
 */
(function() {
    const Formtress = (() => {
        //check if in development by using localhost
        const isDevelopment = window.location.hostname.includes('localhost');
        //warning checks
        (() => {
            if (typeof window === 'undefined') {
                throw new Error('Formtress.js is not supported in this environment.');
            }
            //check if in development by using localhost
            if (isDevelopment) {
                //warning if no noscript element is found
                if (!window.document.querySelector('noscript')) {
                    console.warn('<noscript> element not found. Your site will be vulnerable to all kinds of attacks.');
                }
                //check if formtress is loaded as 1st or 2nd script from the header, remind developer to load it in the first 2 positions
                //within the <head> element
                const scripts = document.querySelectorAll('script');
                if (scripts.length > 1 && scripts[0].src.includes('formtress')) {
                    console.warn('Formtress.js should be loaded as the first or second script in the <head> element to ensure maximum security.');
                }
                //formtress should not be loaded as deferred
                if (scripts.length > 1 && scripts[0].defer) {
                    console.warn('Formtress.js should not be loaded with the defer attribute.');
                }
                //check if body is loaded, if so, warn the developer to load formtress before the body element
                if (!document.body) {
                    console.warn('Formtress.js should be loaded before the body element to ensure maximum security.');
                }
            }
        })();

        const AUTO_CONFIG_KEY = 'FormtressConfig';
        // 1. Freeze core prototypes
        Object.freeze(Object.prototype);
        Object.freeze(Array.prototype);
        // Private storage
        const privateStore = new WeakMap();
        const securedForms = new WeakSet();
        const PRIVATE_KEY = Symbol('formtressPrivate');
        const INIT_TIMEOUT = (() => {
            // Random timeout between 8-12 seconds
            const baseTimeout = 10000;
            const variance = 2000;
            return baseTimeout + (Math.random() * variance * 2 - variance);
        })();
        /**
         * Extensive security patterns and configurations
         */
        const SECURITY_CONFIG = {
            patterns: {
                xss: {
                    minLength: 10,
                    patterns: [
                        /(?=.{10,}).*<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi.source,
                        /(?=.{10,}).*javascript:/gi.source,
                        /(?=.{10,}).*data:\s*text\/html/gi.source,
                        /(?=.{10,}).*vbscript:/gi.source,
                        /(?=.{10,}).*on(?:load|error|click|mouse|focus)\s*=/gi.source,
                        /(?=.{10,}).*<\s*iframe[^>]*src\s*=/gi.source,
                        /(?=.{10,}).*<\s*object[^>]*data\s*=/gi.source,
                        /(?=.{10,}).*<\s*embed[^>]*src\s*=/gi.source,
                        /(?=.{10,}).*expression\s*\(\s*.*\)/gi.source,
                        /(?=.{10,}).*url\s*\(\s*['"]*javascript:/gi.source,
                        /(?=.{10,}).*(?:^|\s|[({])eval\s*\(/gi.source,
                        /(?=.{10,}).*(?:^|\s|[({])(?:alert|prompt|confirm)\s*\(/gi.source,
                        /(?=.{10,}).*new\s+Function\s*\(/gi.source,
                        /(?=.{10,}).*(?:set|clear)(?:Timeout|Interval)\s*\(\s*['"`]/gi.source,
                        /(?=.{10,}).*<[a-zA-Z][^>]*>/gi.source,
                        /(?=.{10,}).*\\x(?:00|22|27)/gi.source,
                        /(?=.{10,}).*\\u(?:0000|0022|0027)/gi.source
                    ],
                    description: 'XSS attempt detected'
                },
                php: {
                    patterns: [
                        /(?=.{10,}).*<\?php/gi.source,      // PHP opening tag
                        /(?=.{10,}).*<\?=/gi.source,        // PHP short echo tag
                        /(?=.{10,}).*phpinfo\s*\(/gi.source,  // phpinfo() call
                        /(?=.{10,}).*system\s*\(/gi.source,   // system() call
                        /(?=.{10,}).*exec\s*\(/gi.source,     // exec() call
                        /(?=.{10,}).*shell_exec\s*\(/gi.source, // shell_exec() call
                        /(?=.{10,}).*passthru\s*\(/gi.source,  // passthru() call
                        /(?=.{10,}).*eval\s*\(/gi.source      // eval() call
                    ],
                    description: 'PHP injection attempt detected'
                },
                python: {
                    patterns: [
                        /(?=.{10,}).*import\s+os/gi.source,     // OS operations
                        /(?=.{10,}).*subprocess\./gi.source,    // Subprocess calls
                        /(?=.{10,}).*exec\(/gi.source,          // Python exec
                        /(?=.{10,}).*eval\(/gi.source,          // Python eval
                        /(?=.{10,}).*open\(/gi.source,          // File operations
                        /(?=.{10,}).*__import__/gi.source       // Dynamic imports
                    ],
                    description: 'Python injection attempt detected'
                },
                ruby: {
                    patterns: [
                        /(?=.{10,}).*`.*`/gi.source,           // Command execution
                        /(?=.{10,}).*system\(/gi.source,       // System calls
                        /(?=.{10,}).*eval\(/gi.source,         // Ruby eval
                        /(?=.{10,}).*File\./gi.source,         // File operations
                        /(?=.{10,}).*IO\./gi.source            // IO operations
                    ],
                    description: 'Ruby injection attempt detected'
                },
                java: {
                    patterns: [
                        /(?=.{10,}).*Runtime\.getRuntime\(\)/gi.source,  // Runtime execution
                        /(?=.{10,}).*ProcessBuilder/gi.source,           // Process creation
                        /(?=.{10,}).*System\.exit/gi.source,             // System operations
                        /(?=.{10,}).*Class\.forName/gi.source            // Dynamic class loading
                    ],
                    description: 'Java injection attempt detected'
                },
                csharp: {
                    patterns: [
                        /(?=.{10,}).*Process\.Start/gi.source,           // Process execution
                        /(?=.{10,}).*Assembly\.Load/gi.source,           // Assembly loading
                        /(?=.{10,}).*System\.Diagnostics/gi.source,      // System operations
                        /(?=.{10,}).*System\.Reflection/gi.source        // Reflection
                    ],
                    description: 'C# injection attempt detected'
                },
                shell: {
                    patterns: [
                        /(?=.{10,}).*\$\([^)]*\)/g.source,           // $(command)
                        /(?=.{10,}).*`[^`]*`/g.source,               // `command`
                        /(?=.{10,}).*\|\s*[a-zA-Z]/g.source,         // pipe operations
                        /(?=.{10,}).*&&\s*[a-zA-Z]/g.source,         // command chaining
                        /(?=.{10,}).*>\s*[a-zA-Z0-9]/g.source,       // output redirection
                        /(?=.{10,}).*<\s*[a-zA-Z0-9]/g.source,       // input redirection
                        /(?=.{10,}).*;\s*[a-zA-Z]/g.source           // command separation
                    ],
                    description: 'Shell command injection attempt detected'
                },
                sql: {
                    patterns: [
                        /(?=.{10,}).*SELECT.+FROM/gi.source,         // SELECT queries
                        /(?=.{10,}).*INSERT.+INTO/gi.source,         // INSERT statements
                        /(?=.{10,}).*UPDATE.+SET/gi.source,          // UPDATE statements
                        /(?=.{10,}).*DELETE.+FROM/gi.source,         // DELETE statements
                        /(?=.{10,}).*DROP.+TABLE/gi.source,          // DROP operations
                        /(?=.{10,}).*UNION.+SELECT/gi.source,        // UNION attacks
                        /(?=.{10,}).*--[\s\S]*$/gi.source,          // SQL comments
                        /(?=.{10,}).*\/\*[\s\S]*?\*\//g.source      // Multi-line comments
                    ],
                    description: 'SQL injection attempt detected'
                },
                prototype: {
                    patterns: [
                        // Property access - with word boundaries and specific context
                        /(?:\[|\.)\s*["']?__proto__["']?\s*(?:\]|\s*=)/g.source,
                        /(?:\[|\.)\s*["']?constructor["']?\s*(?:\]|\s*=)/g.source,
                        /(?:\[|\.)\s*["']?prototype["']?\s*(?:\]|\s*=)/g.source,

                        // Object methods - with word boundaries and function call context
                        /\bObject\.assign\s*\(/g.source,
                        /\bObject\.defineProperty\s*\(/g.source,
                        /\bObject\.setPrototypeOf\s*\(/g.source,
                        /\bObject\.create\s*\(/g.source,

                        // Function constructors - with specific context
                        /\bnew\s+Function\s*\(/g.source,
                        /\bFunction\s*\(\s*["']/g.source,

                        // Dangerous assignments - with specific context
                        /\.\s*__proto__\s*=\s*/g.source,
                        /\.\s*constructor\s*=\s*/g.source,
                        /\.\s*prototype\s*=\s*/g.source,

                        // Reflect operations - with word boundaries
                        /\bReflect\.set\s*\(/g.source,
                        /\bReflect\.defineProperty\s*\(/g.source,
                        /\bReflect\.setPrototypeOf\s*\(/g.source
                    ],
                    description: 'Prototype pollution attempt detected'
                },
                path: {
                    patterns: [
                        /(?:^|[\\/])\.\.\//g.source,  // Only match ../ in path context
                        /(?:^|[\\/])\.\.\\/g.source,  // Only match ..\ in path context

                        // URL encoded - more specific context
                        /(?:\?|&|;).*\.\.%2f/gi.source,  // Match in URL parameters
                        /(?:\?|&|;).*\.\.%5c/gi.source,  // Match in URL parameters

                        // Double-encoded - in URL context
                        /(?:\?|&|;).*%252e%252e%252f/gi.source,
                        /(?:\?|&|;).*%252e%252e%255c/gi.source,

                        // Critical system paths - with boundaries
                        /(?:^|[\\/])(?:etc|proc|sys|var|usr|opt)[\\/]/g.source,

                        // Windows specific - with boundaries
                        /\b[A-Za-z]:\\(?:Windows|System32|Program Files)/gi.source,

                        // Sensitive files - with boundaries and context
                        /(?:^|[\\/])(?:\.htaccess|web\.config|\.env|\.git)[\\/]?$/gi.source,

                        // Null byte - in specific contexts
                        /%00(?:\.|\/).*$/g.source,
                        /\0(?:\.|\/).*$/g.source,

                        // Mixed traversal - with context
                        /(?:^|[\\/])\.\.[\\/]{2,}/g.source,  // Multiple slashes after traversal

                        // Web roots - with boundaries
                        /(?:^|[\\/])(?:www|htdocs|public_html)[\\/]/g.source
                    ],
                    description: 'Path traversal attempt detected'
                },
                command: {
                    patterns: [
                        /\$\([^)]*\)/g.source,           // $(command)
                        /`[^`]*`/g.source,               // `command`

                        // System function calls - with word boundaries
                        /\bsystem\(/g.source,
                        /\bexec\(/g.source,
                        /\bshell_exec\(/g.source,
                        /\bpopen\(/g.source,
                        /\bproc_open\(/g.source,
                        /\bpcntl_exec\(/g.source,

                        // Command chaining - with specific context
                        /\s*;\s*[a-zA-Z]/g.source,       // ; followed by command
                        /\s*\|\s*[a-zA-Z]/g.source,      // | followed by command
                        /\s*&&\s*[a-zA-Z]/g.source,      // && followed by command
                        /\s*\|\|\s*[a-zA-Z]/g.source,    // || followed by command

                        // Variable substitution - with specific context
                        /\$\{[^}]*\}/g.source,           // ${var}

                        // Redirection - with specific context
                        />\s*[a-zA-Z0-9]/g.source,       // > followed by output
                        /<\s*[a-zA-Z0-9]/g.source,       // < followed by input
                        /2>\s*[a-zA-Z0-9]/g.source,      // 2> followed by error output

                        // Environment variables - with specific context
                        /\$ENV\[/g.source,               // $ENV[
                        /\$_[A-Z]+\[/g.source,           // $_GET[, $_POST[, etc.
                        /%[A-Z]+%/g.source               // %PATH%, %HOME%, etc.
                    ],
                    description: 'Command injection attempt detected'
                },
                ajax: {
                    patterns: [
                        // Fetch API patterns
                        /(?=.{10,}).*fetch\s*\(\s*['"`][^'"`]*['"`]\s*\)/gi.source,
                        /(?=.{10,}).*fetch\s*\(\s*window\./gi.source,
                        /(?=.{10,}).*fetch\s*\(\s*location\./gi.source,
                        /(?=.{10,}).*fetch\s*\(\s*document\./gi.source,

                        // XMLHttpRequest patterns
                        /(?=.{10,}).*new\s+XMLHttpRequest\s*\(\s*\)/gi.source,
                        /(?=.{10,}).*\.open\s*\(\s*['"`][^'"`]*['"`]\s*,/gi.source,
                        /(?=.{10,}).*\.send\s*\(\s*.*\)/gi.source,

                        // Common attack patterns
                        /(?=.{10,}).*\.(responseText|responseXML|response)\s*=/gi.source,
                        /(?=.{10,}).*\.(onreadystatechange|onload|onerror)\s*=/gi.source,
                        /(?=.{10,}).*\.(withCredentials|timeout)\s*=/gi.source
                    ],
                    description: 'AJAX injection attempt detected'
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
                validateOnSubmit: true,
                remote: {
                    enabled: false,
                    endpoint: '/api/csrf',
                    method: 'GET',
                    refreshInterval: 300000, // 5 minutes default
                    headers: {
                        'X-Requested-With': 'Formtress'
                    },
                    retryAttempts: 3,
                    retryDelay: 1000
                }
            },
            hooks: {
                beforeValidation: null,
                afterValidation: null,
                beforeSubmit: null,
                afterSubmit: null,
                onError: null
            },
            csp: {
                enabled: false,
                directives: {
                    'default-src': ["'self'"],
                    'script-src': ["'self'", "'strict-dynamic'"],
                    'style-src': ["'self'", "'unsafe-inline'"],
                    'img-src': ["'self'", 'data:', 'https:'],
                    'font-src': ["'self'"],
                    'connect-src': ["'self'"],
                    'frame-src': ["'none'"],
                    'object-src': ["'none'"],
                    'base-uri': ["'self'"],
                    'form-action': ["'self'"],
                    'frame-ancestors': ["'none'"],
                    'upgrade-insecure-requests': [],
                    'block-all-mixed-content': [],
                    'require-trusted-types-for': ["'script'"]
                },
                reportOnly: false,
                reportUri: '/csp-report'
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
        const ConfigLoader = {
            // Existing auto config method
            getAutoConfig() {
                try {
                    const config = window[AUTO_CONFIG_KEY];
                    if (config && Object.isFrozen(config)) {
                        return this.validateRequiredSettings(config);
                    }
                    return null;
                } catch (error) {
                    console.warn('Formtress: Error loading auto-configuration:', error);
                    return null;
                }
            },

            // Add remote config loading
            async loadRemoteConfig(url, options = {}) {
                const {
                    retries = 3,
                    timeout = 5000,
                    validateSignature = true,
                    publicKey = null
                } = options;

                try {
                    // Create abort controller for timeout
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), timeout);

                    // Attempt to fetch with retries
                    let lastError;
                    for (let attempt = 0; attempt < retries; attempt++) {
                        try {
                            const response = await fetch(url, {
                                method: 'GET',
                                credentials: 'same-origin',
                                headers: {
                                    'Accept': 'application/json',
                                    'X-Requested-With': 'Formtress',
                                    'X-Formtress-Version': '0.1.0'
                                },
                                signal: controller.signal
                            });

                            clearTimeout(timeoutId);

                            if (!response.ok) {
                                throw new Error(`HTTP error! status: ${response.status}`);
                            }

                            // Get both config and signature if available
                            const config = await response.json();
                            const signature = response.headers.get('X-Config-Signature');

                            // Validate signature if required
                            if (validateSignature) {
                                if (!signature || !publicKey) {
                                    throw new Error('Configuration signature validation failed: Missing signature or public key');
                                }

                                const isValid = await this.verifySignature(
                                    JSON.stringify(config),
                                    signature,
                                    publicKey
                                );

                                if (!isValid) {
                                    throw new Error('Configuration signature validation failed');
                                }
                            }

                            // Validate and freeze config
                            const validatedConfig = this.validateRequiredSettings(config);
                            return Object.freeze(validatedConfig);

                        } catch (error) {
                            lastError = error;
                            if (error.name === 'AbortError') {
                                console.warn(`Formtress: Config loading timeout (attempt ${attempt + 1}/${retries})`);
                            } else {
                                console.warn(`Formtress: Config loading failed (attempt ${attempt + 1}/${retries}):`, error);
                            }

                            // Wait before retry (exponential backoff)
                            if (attempt < retries - 1) {
                                await new Promise(resolve =>
                                    setTimeout(resolve, Math.pow(2, attempt) * 1000)
                                );
                            }
                        }
                    }

                    throw lastError || new Error('Failed to load remote configuration');

                } catch (error) {
                    console.error('Formtress: Remote configuration loading failed:', error);
                    throw error;
                }
            },

            // Verify cryptographic signature
            async verifySignature(data, signature, publicKey) {
                try {
                    // Convert base64 signature to buffer
                    const signatureBuffer = this.base64ToArrayBuffer(signature);

                    // Import public key
                    const cryptoKey = await crypto.subtle.importKey(
                        'spki',
                        this.base64ToArrayBuffer(publicKey),
                        {
                            name: 'RSASSA-PKCS1-v1_5',
                            hash: 'SHA-256'
                        },
                        false,
                        ['verify']
                    );

                    // Verify signature
                    const dataBuffer = new TextEncoder().encode(data);
                    const isValid = await crypto.subtle.verify(
                        'RSASSA-PKCS1-v1_5',
                        cryptoKey,
                        signatureBuffer,
                        dataBuffer
                    );

                    return isValid;
                } catch (error) {
                    console.error('Formtress: Signature verification failed:', error);
                    return false;
                }
            },

            /**
             * Convert base64 to ArrayBuffer
             * @param {string} base64 - The base64 string to convert
             * @returns {ArrayBuffer} The converted ArrayBuffer
             */
            base64ToArrayBuffer(base64) {
                const binaryString = window.atob(base64);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                return bytes.buffer;
            },

            /**
             * Merge configurations
             * @param {...Object} configs - The configurations to merge
             * @returns {Object} The merged configuration
             */
            mergeConfigs(...configs) {
                return configs.reduce((merged, config) => {
                    if (!config) return merged;
                    return this.secureDeepMerge(merged, config);
                }, {});
            },

            /**
             * Secure deep merge utility
             * @param {Object} target - The target object
             * @param {Object} source - The source object
             * @returns {Object} The merged object
             */
            secureDeepMerge(target, source) {
                const merged = { ...target };

                for (const key in source) {
                    if (Object.prototype.hasOwnProperty.call(source, key)) {
                        if (this.isSecureKey(key)) {
                            if (this.isObject(source[key]) && this.isObject(target[key])) {
                                merged[key] = this.secureDeepMerge(target[key], source[key]);
                            } else {
                                merged[key] = source[key];
                            }
                        }
                    }
                }

                return merged;
            },

            /**
             * Check if a key is secure
             * @param {string} key - The key to check
             * @returns {boolean} Whether the key is secure
             */
            isSecureKey(key) {
                const unsafeKeys = [
                    '__proto__',
                    'constructor',
                    'prototype'
                ];
                return !unsafeKeys.includes(key);
            },

            /**
             * Check if an item is an object
             * @param {any} item - The item to check
             * @returns {boolean} Whether the item is an object
             */
            isObject(item) {
                return item && typeof item === 'object' && !Array.isArray(item);
            }
        };

        class ConfigurationError extends Error {
            constructor(message, path = []) {
                super(message);
                this.name = 'ConfigurationError';
                this.path = path;
            }
        }
        /**
         * Validate configuration against schema
         * @param {Object} config - The configuration to validate
         * @param {Object} schema - The schema to validate against
         * @param {Array} path - The path to the current configuration
         * @returns {Object} The validated configuration
         */
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

        /**
         * Apply configuration to a form
         * @param {HTMLFormElement} form - The form to apply the configuration to
         * @param {Object} config - The configuration to apply
         * @returns {boolean} Whether the configuration was applied successfully
         */
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

        /**
         * Load configuration from JSON
         * @param {string} url - The URL to load the configuration from
         * @returns {Object} The loaded configuration
         */
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

        /**
         * Deep merge utility
         * @param {Object} target - The target object
         * @param {Object} source - The source object
         * @returns {Object} The merged object
         */
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

            /**
             * Check if value is a plain object
             * @param {any} obj - The value to check
             * @returns {boolean} Whether the value is a plain object
             */
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
        /**
         * BrowserFingerprint class for continuous browser environment monitoring
         */
        class BrowserFingerprint {
            constructor(options = {}) {
                this.options = {
                    interval: 5000,
                    threshold: 0.7,
                    autoReload: true,
                    debug: false,
                    reportingEndpoint: '/api/fingerprint',
                    reportingInterval: 300000,
                    cacheKey: 'formtress_fingerprint',
                    ...options
                };
                
                this.violations = [];
                this.lastReportTime = this.getLastReportTime();
                this.init();
            }

            async init() {
                try {
                    const currentHash = await this.generateAndCacheFingerprint();
                    this.startMonitoring();
                } catch (error) {
                    console.error('Failed to initialize BrowserFingerprint:', error);
                }
            }

            async generateAndCacheFingerprint() {
                const fingerprint = await this.generateFingerprint();
                const hash = await this.hashFingerprint(fingerprint);
                
                sessionStorage.setItem(this.options.cacheKey, JSON.stringify({
                    hash,
                    timestamp: Date.now()
                }));

                return hash;
            }

            async checkForChanges() {
                const cachedData = sessionStorage.getItem(this.options.cacheKey);
                if (!cachedData) return true;

                const { hash: oldHash } = JSON.parse(cachedData);
                const newHash = await this.generateAndCacheFingerprint();

                return oldHash !== newHash;
            }

            async sendFingerprintReport() {
                try {
                    // Only send if changes detected or enough time has passed
                    const shouldReport = await this.checkForChanges() || 
                                       (Date.now() - this.lastReportTime >= this.options.reportingInterval);

                    if (!shouldReport) return false;

                    const report = {
                        fingerprint: await this.generateFingerprint(),
                        violations: this.violations,
                        timestamp: Date.now(),
                        sessionId: this.getSessionId()
                    };

                    const response = await fetch(this.options.reportingEndpoint, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Fingerprint-Type': 'browser-report'
                        },
                        body: JSON.stringify(report),
                        credentials: 'same-origin'
                    });

                    if (response.ok) {
                        this.lastReportTime = Date.now();
                        sessionStorage.setItem('formtress_last_report', this.lastReportTime);
                        this.violations = []; // Clear violations after successful report
                        return true;
                    }
                } catch (error) {
                    console.error('Failed to send fingerprint report:', error);
                }
                return false;
            }

            getLastReportTime() {
                return parseInt(sessionStorage.getItem('formtress_last_report')) || 0;
            }

            handleViolation(violation) {
                this.violations.push(violation);
                
                // Store violation in session storage
                const storedViolations = JSON.parse(
                    sessionStorage.getItem('formtress_violations') || '[]'
                );
                storedViolations.push(violation);
                sessionStorage.setItem('formtress_violations', JSON.stringify(storedViolations));

                // Only send immediate report for critical violations
                if (violation.type === 'critical') {
                    this.sendFingerprintReport();
                }
            }

            startMonitoring() {
                setInterval(async () => {
                    const hasChanges = await this.checkForChanges();
                    if (hasChanges) {
                        this.handleViolation({
                            type: 'fingerprint_changed',
                            timestamp: Date.now()
                        });
                    }
                }, this.options.interval);

                // Periodic report sending
                setInterval(() => {
                    this.sendFingerprintReport();
                }, this.options.reportingInterval);
            }

            /**
             * Generate comprehensive browser fingerprint
             */
            async generateFingerprint() {
                const fp = {
                    timestamp: Date.now(),
                    screen: this.getScreenFingerprint(),
                    navigator: this.getNavigatorFingerprint(),
                    window: this.getWindowFingerprint(),
                    system: this.getSystemFingerprint(),
                    webgl: await this.getWebGLFingerprint(),
                    canvas: await this.getCanvasFingerprint(),
                    audio: await this.getAudioFingerprint(),
                    fonts: await this.getFontFingerprint(),
                    plugins: this.getPluginsFingerprint(),
                    performance: this.getPerformanceFingerprint(),
                    network: await this.getNetworkFingerprint()
                };

                // Generate hash of the fingerprint
                fp.hash = await this.hashFingerprint(fp);
                return fp;
            }

            /**
             * Get screen-related fingerprint data
             */
            getScreenFingerprint() {
                return {
                    width: window.screen.width,
                    height: window.screen.height,
                    availWidth: window.screen.availWidth,
                    availHeight: window.screen.availHeight,
                    colorDepth: window.screen.colorDepth,
                    pixelDepth: window.screen.pixelDepth,
                    devicePixelRatio: window.devicePixelRatio,
                    orientation: screen.orientation?.type || null
                };
            }

            /**
             * Get navigator-related fingerprint data
             */
            getNavigatorFingerprint() {
                return {
                    userAgent: navigator.userAgent,
                    language: navigator.language,
                    languages: Array.from(navigator.languages || []),
                    platform: navigator.platform,
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    deviceMemory: navigator.deviceMemory,
                    maxTouchPoints: navigator.maxTouchPoints,
                    cookieEnabled: navigator.cookieEnabled,
                    doNotTrack: navigator.doNotTrack,
                    vendor: navigator.vendor,
                    pdfViewerEnabled: navigator.pdfViewerEnabled,
                    webdriver: navigator.webdriver
                };
            }

            /**
             * Get window-related fingerprint data
             */
            getWindowFingerprint() {
                return {
                    innerWidth: window.innerWidth,
                    innerHeight: window.innerHeight,
                    outerWidth: window.outerWidth,
                    outerHeight: window.outerHeight,
                    screenX: window.screenX,
                    screenY: window.screenY,
                    scrollX: window.scrollX,
                    scrollY: window.scrollY,
                    visualViewport: {
                        width: window.visualViewport?.width,
                        height: window.visualViewport?.height,
                        scale: window.visualViewport?.scale
                    }
                };
            }

            /**
             * Get system-related fingerprint data
             */
            getSystemFingerprint() {
                const timeZone = {
                    offset: new Date().getTimezoneOffset(),
                    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone
                };

                return {
                    timeZone,
                    connection: navigator.connection ? {
                        type: navigator.connection.effectiveType,
                        downlink: navigator.connection.downlink,
                        rtt: navigator.connection.rtt,
                        saveData: navigator.connection.saveData
                    } : null
                };
            }

            /**
             * Get WebGL-related fingerprint data
             */
            async getWebGLFingerprint() {
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    
                    if (!gl) return null;

                    return {
                        vendor: gl.getParameter(gl.VENDOR),
                        renderer: gl.getParameter(gl.RENDERER),
                        version: gl.getParameter(gl.VERSION),
                        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                        extensions: gl.getSupportedExtensions()
                    };
                } catch {
                    return null;
                }
            }

            /**
             * Get canvas-related fingerprint data
             */
            async getCanvasFingerprint() {
                try {
                    const canvas = document.createElement('canvas');
                    canvas.width = 200;
                    canvas.height = 50;
                    
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(125,1,62,20);
                    ctx.fillStyle = '#069';
                    ctx.fillText('Formtress:FP', 2, 15);
                    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                    ctx.fillText('Canvas:Check', 4, 45);
                    
                    return await crypto.subtle.digest('SHA-256', 
                        new TextEncoder().encode(canvas.toDataURL())
                    ).then(hash => Array.from(new Uint8Array(hash))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(''));
                } catch {
                    return null;
                }
            }

            /**
             * Get audio-related fingerprint data
             */
            async getAudioFingerprint() {
                try {
                    // Create audio context only if we haven't stored one yet
                    if (!this.audioContext) {
                        this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
                    }

                    // Check if context is in suspended state
                    if (this.audioContext.state === 'suspended') {
                        // Return a simplified fingerprint if we can't start audio
                        return this.getFallbackAudioFingerprint();
                    }

                    // Modern approach using AnalyserNode only
                    const analyser = this.audioContext.createAnalyser();
                    analyser.fftSize = 2048;

                    // Create and configure oscillator
                    const oscillator = this.audioContext.createOscillator();
                    const gainNode = this.audioContext.createGain();
                    
                    // Mute the sound
                    gainNode.gain.value = 0;
                    
                    // Connect nodes
                    oscillator.connect(analyser);
                    analyser.connect(gainNode);
                    gainNode.connect(this.audioContext.destination);

                    // Get frequency data without starting oscillator
                    const frequencyData = new Float32Array(analyser.frequencyBinCount);
                    analyser.getFloatFrequencyData(frequencyData);

                    // Clean up
                    gainNode.disconnect();
                    analyser.disconnect();

                    // Hash the frequency data
                    return await crypto.subtle.digest('SHA-256',
                        new Float32Array([
                            this.audioContext.sampleRate,
                            this.audioContext.baseLatency || 0,
                            ...frequencyData
                        ]).buffer
                    ).then(hash => Array.from(new Uint8Array(hash))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(''));

                } catch (error) {
                    return this.getFallbackAudioFingerprint();
                }
            }

            /**
             * Get fallback audio fingerprint when audio context is not available
             */
            async getFallbackAudioFingerprint() {
                // Create a fingerprint from available audio properties
                const audioProps = {
                    audioWorklet: 'AudioWorklet' in window,
                    webAudio: 'AudioContext' in window || 'webkitAudioContext' in window,
                    audioCodecs: {
                        mp3: this.checkMediaType('audio/mp3'),
                        wav: this.checkMediaType('audio/wav'),
                        ogg: this.checkMediaType('audio/ogg'),
                        m4a: this.checkMediaType('audio/m4a'),
                        aac: this.checkMediaType('audio/aac')
                    },
                    sampleRate: this.audioContext?.sampleRate || null,
                    channelCount: this.audioContext?.destination?.maxChannelCount || null
                };

                // Convert to string and hash
                return crypto.subtle.digest('SHA-256',
                    new TextEncoder().encode(JSON.stringify(audioProps))
                ).then(hash => Array.from(new Uint8Array(hash))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join(''));
            }

            /**
             * Check if media type is supported
             */
            checkMediaType(mimeType) {
                const audio = document.createElement('audio');
                return audio.canPlayType(mimeType) || null;
            }

            /**
             * Initialize audio context on user interaction
             */
            initAudioContext() {
                const initContext = () => {
                    if (!this.audioContext) {
                        this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
                    }
                    // Remove listeners after first interaction
                    document.removeEventListener('click', initContext);
                };
                // Add listener for user interaction
                document.addEventListener('click', initContext);
            }

            /**
             * Get font-related fingerprint data
             */
            async getFontFingerprint() {
                const baseFonts = ['monospace', 'sans-serif', 'serif'];
                const testString = 'mmmmmmmmmmlli';
                const testSize = '72px';
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');

                const getFontWidth = (fontFamily) => {
                    ctx.font = `${testSize} ${fontFamily}`;
                    return ctx.measureText(testString).width;
                };

                const baseWidths = baseFonts.map(getFontWidth);
                const fontList = [
                    'Arial', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana',
                    'Helvetica', 'Comic Sans MS', 'Trebuchet MS', 'Impact'
                ];

                const detectedFonts = fontList.filter(font => {
                    return baseFonts.some((baseFont, index) => {
                        ctx.font = `${testSize} ${font}, ${baseFont}`;
                        return ctx.measureText(testString).width !== baseWidths[index];
                    });
                });

                return detectedFonts;
            }

            /**
             * Get plugin-related fingerprint data
             */
            getPluginsFingerprint() {
                return Array.from(navigator.plugins || []).map(plugin => ({
                    name: plugin.name,
                    description: plugin.description,
                    filename: plugin.filename
                }));
            }

            /**
             * Get performance-related fingerprint data
             */
            getPerformanceFingerprint() {
                const timing = window.performance.timing;
                return {
                    timing: {
                        navigationStart: timing.navigationStart,
                        loadEventEnd: timing.loadEventEnd,
                        domComplete: timing.domComplete,
                        domInteractive: timing.domInteractive,
                        domContentLoadedEventEnd: timing.domContentLoadedEventEnd
                    },
                    memory: window.performance.memory ? {
                        jsHeapSizeLimit: window.performance.memory.jsHeapSizeLimit,
                        totalJSHeapSize: window.performance.memory.totalJSHeapSize,
                        usedJSHeapSize: window.performance.memory.usedJSHeapSize
                    } : null
                };
            }

            /**
             * Get network-related fingerprint data
             */
            async getNetworkFingerprint() {
                return {
                    connection: navigator.connection ? {
                        effectiveType: navigator.connection.effectiveType,
                        downlink: navigator.connection.downlink,
                        rtt: navigator.connection.rtt,
                        saveData: navigator.connection.saveData
                    } : null,
                    // Add more network-related checks here
                };
            }

            /**
             * Hash the fingerprint data
             */
            async hashFingerprint(fingerprint) {
                const jsonString = JSON.stringify(fingerprint);
                const hashBuffer = await crypto.subtle.digest('SHA-256', 
                    new TextEncoder().encode(jsonString)
                );
                return Array.from(new Uint8Array(hashBuffer))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            }

            /**
             * Stop monitoring
             */
            stop() {
                if (this.monitoringInterval) {
                    clearInterval(this.monitoringInterval);
                    this.monitoringInterval = null;
                }
            }

            /**
             * Get violation history
             */
            getViolations() {
                return [...this.violations];
            }

            // Helper method to get/generate session ID
            getSessionId() {
                if (!this.sessionId) {
                    this.sessionId = crypto.randomUUID();
                }
                return this.sessionId;
            }
        }

        const fingerprint = new BrowserFingerprint({
            interval: 5000,  // Check every 5 seconds
            threshold: 0.7,  // 70% similarity threshold
            autoReload: true,
            debug: false
        });
        // Core security class
        class SecurityCore {
            constructor(config) {
                this.violations = [];
                this.config = deepMerge(SECURITY_CONFIG, config);
                this.patterns = this.cloneSecurityPatterns(SECURITY_CONFIG.patterns);

                // Initialize CSRF settings
                this.initializeCsrf(config?.csrf);

                this.commonCsrfNames = [
                    '_csrf',
                    'csrf_token',
                    'csrf-token',
                    'csrfToken',
                    'csrfmiddlewaretoken',    // Django
                    '_token',                 // Laravel
                    '__RequestVerificationToken', // ASP.NET
                    'XSRF-TOKEN',            // Angular
                    'X-CSRF-Token',          // Rails
                    'authenticity_token'      // Rails
                ];
            }

            /**
             * Initialize CSRF settings and detect existing tokens
             * @param {Object} csrfConfig - CSRF configuration
             */
            async initializeCsrf(csrfConfig = {}) {
                this.csrfEnabled = csrfConfig?.enabled ?? false;
                this.csrfFieldName = csrfConfig?.fieldName ?? '_csrf';
                this.csrfDetected = false;
                
                if (this.csrfEnabled && csrfConfig?.remote?.enabled) {
                    await this.setupRemoteCsrf(csrfConfig.remote);
                }
            }

            async setupRemoteCsrf(remoteConfig) {
                // First try to detect existing CSRF token
                const existingToken = this.detectExistingCsrfToken();
                if (existingToken) {
                    this.csrfFieldName = existingToken.name;
                    this.csrfDetected = true;
                    return;
                }

                // If no existing token, proceed with remote fetching
                const fetchToken = async (retryCount = 0) => {
                    try {
                        const response = await fetch(remoteConfig.endpoint, {
                            method: remoteConfig.method,
                            headers: remoteConfig.headers,
                            credentials: 'same-origin'
                        });

                        if (!response.ok) throw new Error('CSRF fetch failed');
                        
                        const data = await response.json();
                        return data.token;
                    } catch (error) {
                        if (retryCount < remoteConfig.retryAttempts) {
                            await new Promise(resolve => 
                                setTimeout(resolve, remoteConfig.retryDelay * Math.pow(2, retryCount))
                            );
                            return fetchToken(retryCount + 1);
                        }
                        throw error;
                    }
                };

                const updateCsrfToken = async () => {
                    try {
                        const token = await fetchToken();
                        this.updateCsrfField(token);
                    } catch (error) {
                        console.error('Failed to refresh CSRF token:', error);
                    }
                };

                // Initial token fetch
                await updateCsrfToken();

                // Set up refresh interval
                if (remoteConfig.refreshInterval > 0) {
                    setInterval(updateCsrfToken, remoteConfig.refreshInterval);
                }
            }

            updateCsrfField(token) {
                const forms = document.querySelectorAll('form[data-formtress-secured]');
                forms.forEach(form => {
                    // First check if there's an existing CSRF input with any common name
                    let csrfInput = null;
                    for (const name of this.commonCsrfNames) {
                        const existing = form.querySelector(`input[name="${name}"]`);
                        if (existing) {
                            csrfInput = existing;
                            break;
                        }
                    }
                    
                    // If no existing input found, create new one
                    if (!csrfInput) {
                        csrfInput = document.createElement('input');
                        csrfInput.type = 'hidden';
                        csrfInput.name = this.csrfFieldName;
                        form.appendChild(csrfInput);
                    }
                    
                    csrfInput.value = token;
                });
            }

            /**
             * Detect existing CSRF token in form
             * @param {HTMLFormElement} form - The form to check
             * @returns {boolean} Whether CSRF token was detected
             */
            detectCsrf(form) {
                if (!form || !(form instanceof HTMLFormElement)) return false;

                // Check for existing CSRF input
                const existingCsrf = form.querySelector(`input[name="${this.csrfFieldName}"]`);
                if (existingCsrf) {
                    this.csrfDetected = true;
                    return true;
                }

                for (const name of this.commonCsrfNames) {
                    const field = form.querySelector(`input[name="${name}"]`);
                    if (field) {
                        // Update our field name to match the detected one
                        this.csrfFieldName = name;
                        this.csrfDetected = true;
                        return true;
                    }
                }

                return false;
            }

            /**
             * Validate CSRF
             * @param {HTMLFormElement} form - The form to validate
             * @returns {boolean} Whether the CSRF validation is successful
             */
            validateCsrf(form) {
                // If CSRF is not enabled and not detected, skip validation
                if (!this.csrfEnabled && !this.csrfDetected) {
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
                    // Skip XSS check if string length is less than minLength
                    if (key === 'xss' && value.length < (this.config.patterns.xss.minLength || 10)) {
                        continue;
                    }

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

                // Only sanitize if string length is >= minLength (10 chars)
                if (value.length >= this.config.patterns.xss.minLength) {
                    return value
                        // Only replace < > when they're part of HTML-like patterns
                        .replace(/<script|<iframe|<embed|<object/gi, '') // Only catch dangerous HTML tags
                        .replace(/javascript:/gi, '')
                        .replace(/data:\s*text\/html/gi, '')
                        .replace(/vbscript:/gi, '')
                        .replace(/on(?:load|error|click|mouse|focus)\s*=/gi, '');
                }

                // Return original value for short strings
                return value;
            }

            detectExistingCsrfToken() {
                const forms = document.querySelectorAll('form[data-formtress-secured]');
                
                for (const form of forms) {
                    // Check all common CSRF names
                    for (const name of this.commonCsrfNames) {
                        const field = form.querySelector(`input[name="${name}"]`);
                        if (field && field.value) {
                            return { name, value: field.value };
                        }

                        // Also check for meta tags (common in Rails, Laravel)
                        const metaTag = document.querySelector(`meta[name="${name}"]`);
                        if (metaTag && metaTag.content) {
                            return { name, value: metaTag.content };
                        }
                    }
                }

                return null;
            }
        }

        // Rate limiter implementation
        class RateLimiter {
            constructor(options = {}) {
                this.options = {
                    windowMs: 60000,           // Default: 1 minute window
                    maxAttempts: 30,           // Default: 30 attempts per window
                    blockDuration: 300000,     // Default: 5 minutes block duration
                    skipFailedAttempts: false, // Whether to count failed attempts
                    whitelist: new Set(),      // Whitelisted identifiers
                    blacklist: new Set(),      // Blacklisted identifiers
                    customKeyGenerator: null,  // Custom key generator function
                    onLimitReached: null,      // Callback when limit is reached
                    gradualDelay: true,        // Enable gradual delay increase
                    delayAfter: 10,           // Start adding delays after X attempts
                    delayFactor: 1000,        // Ms to multiply by attempt count
                    maxDelay: 10000,          // Maximum delay in milliseconds
                    ...options
                };

                this.attempts = new Map();     // Store attempts
                this.blocked = new Map();      // Store blocked status
                this.stats = {
                    totalAttempts: 0,
                    blockedAttempts: 0,
                    currentlyBlocked: 0,
                    whitelisted: 0,
                    blacklisted: 0
                };
            }

            /**
             * Generate a rate limit key
             * @param {string} identifier - Base identifier
             * @returns {string} Generated key
             */
            generateKey(identifier) {
                if (this.options.customKeyGenerator) {
                    return this.options.customKeyGenerator(identifier);
                }
                return `${identifier}_${Math.floor(Date.now() / this.options.windowMs)}`;
            }

            /**
             * Check if an identifier is currently blocked
             * @param {string} identifier - The identifier to check
             * @returns {boolean} Whether the identifier is blocked
             */
            isBlocked(identifier) {
                const blockedUntil = this.blocked.get(identifier);
                if (blockedUntil && blockedUntil > Date.now()) {
                    return true;
                }
                this.blocked.delete(identifier);
                return false;
            }

            /**
             * Calculate delay based on attempt count
             * @param {number} attempts - Number of attempts
             * @returns {number} Delay in milliseconds
             */
            calculateDelay(attempts) {
                if (!this.options.gradualDelay || attempts <= this.options.delayAfter) {
                    return 0;
                }

                const excess = attempts - this.options.delayAfter;
                const delay = Math.min(
                    excess * this.options.delayFactor,
                    this.options.maxDelay
                );

                return delay;
            }

            /**
             * Check the rate limit
             * @param {string} identifier - The identifier to check
             * @param {Object} options - Additional options for this check
             * @returns {Object} Rate limit check result
             */
            async checkLimit(identifier, options = {}) {
                this.stats.totalAttempts++;

                // Check whitelist
                if (this.options.whitelist.has(identifier)) {
                    this.stats.whitelisted++;
                    return {
                        allowed: true,
                        remaining: Infinity,
                        delay: 0,
                        whitelisted: true
                    };
                }

                // Check blacklist
                if (this.options.blacklist.has(identifier)) {
                    this.stats.blacklisted++;
                    return {
                        allowed: false,
                        remaining: 0,
                        delay: 0,
                        blacklisted: true
                    };
                }

                // Check if blocked
                if (this.isBlocked(identifier)) {
                    this.stats.blockedAttempts++;
                    return {
                        allowed: false,
                        remaining: 0,
                        delay: 0,
                        blocked: true,
                        resetTime: this.blocked.get(identifier)
                    };
                }

                const key = this.generateKey(identifier);
                const now = Date.now();
                const windowStart = now - this.options.windowMs;

                // Get attempts for this window
                let attempts = this.attempts.get(key) || [];
                attempts = attempts.filter(timestamp => timestamp > windowStart);

                // Calculate delay if gradual delay is enabled
                const delay = this.calculateDelay(attempts.length);

                // Check if limit exceeded
                if (attempts.length >= this.options.maxAttempts) {
                    this.blocked.set(identifier, now + this.options.blockDuration);
                    this.stats.currentlyBlocked++;

                    if (this.options.onLimitReached) {
                        await this.options.onLimitReached(identifier, {
                            attempts: attempts.length,
                            window: this.options.windowMs,
                            blockDuration: this.options.blockDuration
                        });
                    }

                    return {
                        allowed: false,
                        remaining: 0,
                        delay,
                        blocked: true,
                        resetTime: now + this.options.blockDuration
                    };
                }

                // Add new attempt
                attempts.push(now);
                this.attempts.set(key, attempts);

                return {
                    allowed: true,
                    remaining: this.options.maxAttempts - attempts.length,
                    delay,
                    resetTime: windowStart + this.options.windowMs
                };
            }

            /**
             * Add an identifier to the whitelist
             * @param {string} identifier - The identifier to whitelist
             */
            whitelist(identifier) {
                this.options.whitelist.add(identifier);
                this.blocked.delete(identifier);
            }

            /**
             * Add an identifier to the blacklist
             * @param {string} identifier - The identifier to blacklist
             */
            blacklist(identifier) {
                this.options.blacklist.add(identifier);
                this.attempts.delete(this.generateKey(identifier));
            }

            /**
             * Reset limits for an identifier
             * @param {string} identifier - The identifier to reset
             */
            reset(identifier) {
                const key = this.generateKey(identifier);
                this.attempts.delete(key);
                this.blocked.delete(identifier);
            }

            /**
             * Get current stats for an identifier
             * @param {string} identifier - The identifier to check
             * @returns {Object} Current rate limit stats
             */
            getStats(identifier) {
                const key = this.generateKey(identifier);
                const attempts = this.attempts.get(key) || [];
                const blocked = this.blocked.get(identifier);

                return {
                    attempts: attempts.length,
                    remaining: Math.max(0, this.options.maxAttempts - attempts.length),
                    blocked: blocked ? blocked > Date.now() : false,
                    resetTime: blocked || (Math.floor(Date.now() / this.options.windowMs) + 1) * this.options.windowMs,
                    whitelisted: this.options.whitelist.has(identifier),
                    blacklisted: this.options.blacklist.has(identifier)
                };
            }

            /**
             * Clean up old rate limit data
             */
            cleanup() {
                const now = Date.now();
                const windowStart = now - this.options.windowMs;

                // Clean up attempts
                for (const [key, timestamps] of this.attempts.entries()) {
                    const valid = timestamps.filter(timestamp => timestamp > windowStart);
                    if (valid.length === 0) {
                        this.attempts.delete(key);
                    } else {
                        this.attempts.set(key, valid);
                    }
                }

                // Clean up blocked status
                for (const [identifier, blockedUntil] of this.blocked.entries()) {
                    if (blockedUntil <= now) {
                        this.blocked.delete(identifier);
                        this.stats.currentlyBlocked--;
                    }
                }
            }

            /**
             * Get global statistics
             * @returns {Object} Global rate limit statistics
             */
            getGlobalStats() {
                this.cleanup(); // Clean up before returning stats
                return {
                    ...this.stats,
                    activeWindows: this.attempts.size,
                    timestamp: Date.now()
                };
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
                // Random debugger placement
                const debugTrap = (() => {
                    let counter = 0;

                    // DevTools detection methods
                    const detectDevTools = () => {
                        const checks = [
                            // Method 1: More accurate window size check for undocked devtools
                            (() => {
                                const widthThreshold = window.outerWidth - window.innerWidth > 160;
                                const heightThreshold = window.outerHeight - window.innerHeight > 160;
                                return widthThreshold && heightThreshold;  // Must meet both conditions
                            })(),

                            // Method 2: More reliable performance timing check
                            (() => {
                                const start = performance.now();
                                debugger;
                                const end = performance.now();
                                return (end - start) > 200;  // Increased threshold for reliability
                            })(),

                            // Method 3: Dev tools object check
                            (() => {
                                const isFirebug = window.console && window.console.firebug;
                                const isChrome = window.chrome && window.chrome.devtools;
                                return isFirebug || isChrome;
                            })()
                        ];

                        // Require at least 2 checks to be true to reduce false positives
                        return checks.filter(Boolean).length >= 2;
                    };

                    return () => {
                        // Increment counter
                        counter++;

                        // Check for excessive debugging
                        if (counter > 100) {
                            console.warn('Excessive debugging detected');
                           window.location.reload();
                            return;
                        }

                        // Only proceed if DevTools are actually detected
                        if (detectDevTools()) {
                            console.warn('DevTools detected');
                            const noise = crypto.getRandomValues(new Uint8Array(1))[0];

                            // Force reload after long debugging session
                            const debugStart = performance.now();
                            debugger;
                            const debugEnd = performance.now();

                            if (debugEnd - debugStart > 5000) { // 5 seconds debug timeout
                                window.location.reload();
                                return true;
                            }

                            // Random reload for shorter sessions
                            if (noise % 4 === 0) {
                                window.location.reload();
                            }
                            return true;
                        }

                        return false;
                    };
                })();

                // More conservative monitoring interval
                const startDevToolsMonitoring = () => {
                    let debugStartTime = null;

                    const monitor = setInterval(() => {
                        try {
                            if (detectDevTools()) {
                                if (!debugStartTime) {
                                    debugStartTime = performance.now();
                                } else if (performance.now() - debugStartTime > 10000) { // 10 seconds total debug time
                                    console.warn('Long debugging session detected, reloading...');
                                    window.location.reload();
                                }
                            } else {
                                debugStartTime = null;
                            }
                        } catch (error) {
                            clearInterval(monitor);
                        }
                    }, 1000);

                    // Cleanup after 5 minutes if no issues
                    setTimeout(() => clearInterval(monitor), 5 * 60 * 1000);
                };

                // Add some random delay to make timing attacks harder
                const randomDelay = Math.random() * 100;
                setTimeout(() => {
                    debugTrap(); // First trap

                    const initStart = performance.now();

                    // Set up initialization timeout
                    const initTimeout = setTimeout(() => {
                        if (performance.now() - initStart > 10000) { // 10 seconds init timeout
                            console.warn('Formtress: Initialization took too long, reloading page...');
                            window.location.reload();
                        }
                    }, 10000);

                    try {
                        debugTrap(); // Second trap

                        // Try to load auto-configuration
                        const autoConfig = ConfigLoader.getAutoConfig();

                        debugTrap(); // Third trap

                        // Merge configurations with priority
                        const config = deepMerge(
                            SECURITY_CONFIG,
                            deepMerge(autoConfig || {}, customConfig)
                        );

                        debugTrap(); // Fourth trap

                        const secureConfig = SecureFormtressConfigInjector.lockConfig(form, config);
                        const secure = {
                            form: form,
                            config: config,
                            security: new SecurityCore(config.security),
                            rateLimiter: config.rateLimit.enabled ? new RateLimiter(config.rateLimit) : null,
                            fields: new Map(),
                            lastSubmit: 0,
                            csp: new CSPCore(config.csp),
                            debouncedValidations: new Map()
                        };

                        debugTrap(); // Fifth trap

                        privateStore.set(this, secure);
                        this.initializeForm();

                        // Clear timeout if initialization completes successfully
                        clearTimeout(initTimeout);

                        // Start monitoring after successful init
                        setTimeout(startDevToolsMonitoring, 1000);

                    } catch (error) {
                        debugTrap(); // Error trap
                        clearTimeout(initTimeout);
                        console.error('Formtress: Configuration error detected.',error);
                        //window.location.reload();
                    }
                }, randomDelay);
            }
            /**
             * Get the CSP nonce
             * @returns {string} The CSP nonce
             */
            getCSPNonce() {
                const state = privateStore.get(this);
                return state.csp.getNonce();
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

                // Detect existing CSRF token
                state.security.detectCsrf(form);

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
                const debouncedValidation = ((fn, delay) => {
                    let timeoutId;
                    return (...args) => {
                        clearTimeout(timeoutId);
                        timeoutId = setTimeout(() => fn.apply(this, args), delay);
                    };
                })(() => this.validateField(name), state.config.validation.debounce);

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

                // Add transition styles if not already present
                container.style.transition = 'all 0.3s ease-in-out';
                container.style.opacity = '0';

                // Use setTimeout to ensure the opacity transition is visible
                setTimeout(() => {
                    container.className = `formtress-result formtress-${type}`;

                    if (type === 'loading') {
                        container.textContent = '⟳';
                        container.style.color = '#666';
                        container.style.animation = 'formtress-spin 1s linear infinite';

                        // Add keyframes for spin animation if not already present
                        if (!document.querySelector('#formtress-spin-keyframes')) {
                            const keyframes = document.createElement('style');
                            keyframes.id = 'formtress-spin-keyframes';
                            keyframes.textContent = `
                            @keyframes formtress-spin {
                                from { transform: rotate(0deg); }
                                to { transform: rotate(360deg); }
                            }
                        `;
                            document.head.appendChild(keyframes);
                        }
                    } else {
                        container.style.animation = 'none';
                        container.className = `formtress-result formtress-${type}`;
                        container.textContent = type === 'success' ? config.successSymbol : `${config.errorSymbol} ${message}`;
                        container.style.color = type === 'success' ? config.successColor : config.errorColor;
                    }

                    container.style.opacity = '1';
                }, 50);
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
                                if (node.nodeName === 'FORM' && !node.dataset.formtressSecured) {
                                    this.secureForm(node);
                                }
                                node.querySelectorAll('form:not([data-formtress-secured])')
                                    .forEach(form => this.secureForm(form));
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
                    .replace(/on\w+=/gi, '');
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
                    .replace(/on\w+=/gi, '');
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
                    .replace(/vbscript:/gi, '');
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
        /**
         * CSP Core
         */
        class CSPCore {
            // List of directives that only work with HTTP headers
            static HEADER_ONLY_DIRECTIVES = new Set([
                'frame-ancestors',
                'report-uri',
                'report-to',
                'sandbox'
            ]);

            constructor(config) {
                this.config = {
                    ...config,
                    directives: Object.fromEntries(
                        Object.entries(config.directives).map(([key, value]) => [key, [...value]])
                    )
                };

                this.nonce = this.generateNonce();

                if (this.config.enabled) {
                    this.applyCSP();
                    this.updateExistingScripts();
                }
            }

            generateNonce() {
                // Generate a random nonce for CSP
                const array = new Uint8Array(16);
                crypto.getRandomValues(array);
                return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
            }

            buildCSPString() {
                const directives = this.config.directives;
                const parts = [];

                for (const [directive, values] of Object.entries(directives)) {
                    // Skip directives that only work with HTTP headers
                    if (CSPCore.HEADER_ONLY_DIRECTIVES.has(directive)) {
                        continue;
                    }

                    if (values.length > 0) {
                        const directiveValues = [...values];
                        if (directive === 'script-src' || directive === 'style-src') {
                            directiveValues.push(`'nonce-${this.nonce}'`);
                        }
                        parts.push(`${directive} ${directiveValues.join(' ')}`);
                    } else if (values.length === 0 && directive !== 'report-uri') {
                        parts.push(directive);
                    }
                }

                return parts.join('; ');
            }

            applyCSP() {
                const cspString = this.buildCSPString();
                const header = this.config.reportOnly ?
                    'Content-Security-Policy-Report-Only' :
                    'Content-Security-Policy';

                // Apply CSP via meta tag
                const meta = document.createElement('meta');
                meta.httpEquiv = header;
                meta.content = cspString;
                document.head.appendChild(meta);

                // Log information about header-only directives if they're present
                const headerOnlyDirectives = Object.keys(this.config.directives)
                    .filter(directive => CSPCore.HEADER_ONLY_DIRECTIVES.has(directive));

                if (headerOnlyDirectives.length > 0) {
                    console.info(
                        'Formtress CSP: The following directives require HTTP headers and will be ignored in meta tag:\n' +
                        headerOnlyDirectives.join(', ') +
                        '\nPlease configure these directives server-side.'
                    );
                }

                // Set up violation reporting if a report-uri is configured
                if (this.config.reportUri) {
                    document.addEventListener('securitypolicyviolation', (e) => {
                        this.handleCSPViolation(e);
                    });
                }
            }

            handleCSPViolation(event) {
                const violationReport = {
                    documentUri: event.documentURI,
                    violatedDirective: event.violatedDirective,
                    effectiveDirective: event.effectiveDirective,
                    originalPolicy: event.originalPolicy,
                    blockedUri: event.blockedURI,
                    lineNumber: event.lineNumber,
                    columnNumber: event.columnNumber,
                    sourceFile: event.sourceFile,
                    statusCode: event.statusCode,
                    timestamp: new Date().toISOString()
                };

                // Send violation report
                if (this.config.reportUri) {
                    fetch(this.config.reportUri, {
                        method: 'POST',
                        body: JSON.stringify({ 'csp-report': violationReport }),
                        headers: { 'Content-Type': 'application/csp-report' }
                    }).catch(error => {
                        console.error('Failed to send CSP violation report:', error);
                    });
                }

                // Emit event for violation
                const dispatchEvent = new CustomEvent('formtress:csp-violation', {
                    detail: violationReport
                });
                document.dispatchEvent(dispatchEvent);
            }

            getNonce() {
                return this.nonce;
            }

            /**
             * Update CSP configuration at runtime
             * @param {Object} newConfig - New CSP configuration
             */
            updateConfig(newConfig) {
                this.config = { ...this.config, ...newConfig };
                if (this.config.enabled) {
                    this.applyCSP();
                    this.updateExistingScripts();
                }
            }

            /**
             * Get current CSP configuration
             * @returns {Object} Current CSP configuration
             */
            getConfig() {
                return { ...this.config };
            }

            updateExistingScripts() {
                // Update all inline scripts with the nonce
                document.querySelectorAll('script:not([src])').forEach(script => {
                    script.nonce = this.nonce;
                });
            }

            // Helper method to create new script elements with nonce
            createScript(content) {
                const script = document.createElement('script');
                script.nonce = this.nonce;
                script.textContent = content;
                return script;
            }
        }
        // Global observer for automatic form discovery
        class FormtressObserver {
            constructor() {
                this.init();
            }
            init() {
                this.secureExistingForms();
                // Initialize when DOM is ready
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', () => {
                        this.startObserving();
                    });
                } else {
                    this.startObserving();
                }
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

        /**
         * Create a secure function
         * @param {function} code - The function to secure
         * @returns {function} The secure function
         */
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

        /**
         * Enhanced debounce function with additional features
         * @param {Function} func - The function to debounce
         * @param {number} wait - The debounce wait time in milliseconds
         * @param {Object} options - Additional options
         * @returns {Function} The debounced function
         */
        const createDebounce = (func, wait = 0, options = {}) => {
            const {
                leading = false,      // Execute on the leading edge
                trailing = true,      // Execute on the trailing edge
                maxWait = null,       // Maximum time to wait before forcing execution
                rejectOnCancel = false // Whether to reject the promise if cancelled
            } = options;

            let timeoutId = null;
            let maxTimeoutId = null;
            let lastArgs = null;
            let lastThis = null;
            let lastCallTime = null;
            let lastExecuteTime = null;
            let resolvers = [];
            let rejecters = [];

            // Clear all timeouts
            const clearTimeouts = () => {
                if (timeoutId) {
                    clearTimeout(timeoutId);
                    timeoutId = null;
                }
                if (maxTimeoutId) {
                    clearTimeout(maxTimeoutId);
                    maxTimeoutId = null;
                }
            };

            // Execute the function
            const execute = () => {
                const args = lastArgs;
                const thisArg = lastThis;
                
                // Reset state
                lastArgs = lastThis = null;
                lastExecuteTime = Date.now();
                
                try {
                    const result = func.apply(thisArg, args);
                    resolvers.forEach(resolve => resolve(result));
                } catch (error) {
                    rejecters.forEach(reject => reject(error));
                } finally {
                    resolvers = [];
                    rejecters = [];
                }
            };

            // Create the debounced function
            const debounced = function(...args) {
                lastArgs = args;
                lastThis = this;
                lastCallTime = Date.now();

                // Create new promise for this call
                const promise = new Promise((resolve, reject) => {
                    resolvers.push(resolve);
                    rejecters.push(reject);
                });

                // Handle leading edge execution
                const shouldExecuteNow = leading && !timeoutId;
                if (shouldExecuteNow) {
                    execute();
                    return promise;
                }

                // Clear existing timeout
                clearTimeouts();

                // Set up new timeout
                timeoutId = setTimeout(() => {
                    if (trailing) {
                        execute();
                    }
                    clearTimeouts();
                }, wait);

                // Set up maxWait timeout if specified
                if (maxWait && !maxTimeoutId) {
                    maxTimeoutId = setTimeout(() => {
                        if (lastArgs) {
                            execute();
                        }
                        clearTimeouts();
                    }, maxWait);
                }

                return promise;
            };

            // Add cancel method
            debounced.cancel = () => {
                if (lastArgs && rejectOnCancel) {
                    const error = new Error('Debounced function cancelled');
                    rejecters.forEach(reject => reject(error));
                    resolvers = [];
                    rejecters = [];
                }
                lastArgs = lastThis = null;
                clearTimeouts();
            };

            // Add flush method
            debounced.flush = () => {
                if (lastArgs) {
                    execute();
                    clearTimeouts();
                }
            };

            // Add pending check
            debounced.pending = () => {
                return !!lastArgs;
            };

            return debounced;
        };

        // Initialize observer
        const observer = new FormtressObserver();

        // Add after the CONFIG_SCHEMA definition:
        const SecureAjaxWrapper = (() => {
            // Store original methods in closure
            const originalFetch = window.fetch;
            const originalXHR = window.XMLHttpRequest;

            // Add AjaxMonitor first since it's used by other functions
            const AjaxMonitor = {
                requests: new Map(),
                stats: {
                    fetch: { success: 0, failed: 0, blocked: 0 },
                    xhr: { success: 0, failed: 0, blocked: 0 }
                },

                startRequest(type, url, options = {}) {
                    const requestId = crypto.randomUUID();
                    const timestamp = Date.now();

                    this.requests.set(requestId, {
                        type,
                        url,
                        options,
                        startTime: timestamp,
                        status: 'pending'
                    });

                    this.dispatchEvent('request:start', {
                        requestId,
                        type,
                        url,
                        timestamp,
                        options
                    });

                    return requestId;
                },

                endRequest(requestId, status, response = null, error = null) {
                    const request = this.requests.get(requestId);
                    if (!request) return;

                    const duration = Date.now() - request.startTime;
                    const finalStatus = status === 'success' ? 'success' : 'failed';

                    this.stats[request.type][finalStatus]++;

                    request.status = finalStatus;
                    request.duration = duration;
                    request.response = response;
                    request.error = error;

                    this.dispatchEvent('request:end', {
                        requestId,
                        type: request.type,
                        url: request.url,
                        duration,
                        status: finalStatus,
                        response,
                        error
                    });

                    this.cleanup();
                },

                blockRequest(type, url, reason) {
                    this.stats[type].blocked++;

                    this.dispatchEvent('request:blocked', {
                        type,
                        url,
                        reason,
                        timestamp: Date.now()
                    });
                },

                dispatchEvent(eventName, detail) {
                    const event = new CustomEvent(`formtress:ajax:${eventName}`, {
                        detail: {
                            ...detail,
                            timestamp: Date.now()
                        }
                    });
                    document.dispatchEvent(event);

                    if (this.isDebugEnabled()) {
                        console.debug(`Formtress Ajax Monitor - ${eventName}:`, detail);
                    }
                },

                cleanup() {
                    const hour = 60 * 60 * 1000;
                    const maxRequests = 100;
                    const now = Date.now();

                    let requests = Array.from(this.requests.entries());
                    requests = requests.filter(([_, req]) => now - req.startTime < hour);

                    if (requests.length > maxRequests) {
                        requests = requests.slice(-maxRequests);
                    }

                    this.requests = new Map(requests);
                },

                getStats() {
                    return {
                        ...this.stats,
                        activeRequests: Array.from(this.requests.values())
                            .filter(req => req.status === 'pending').length,
                        timestamp: Date.now()
                    };
                },

                isDebugEnabled() {
                    return localStorage.getItem('formtress:ajax:debug') === 'true';
                },

                reset() {
                    this.requests.clear();
                    this.stats = {
                        fetch: { success: 0, failed: 0, blocked: 0 },
                        xhr: { success: 0, failed: 0, blocked: 0 }
                    };
                }
            };

            // Define secure URL validator before secureFetch
            const isSecureUrl = (url) => {
                try {
                    const urlObj = new URL(url, window.location.origin);
                    if (urlObj.origin !== window.location.origin) {
                        console.warn('Formtress: Cross-origin request detected:', urlObj.origin);
                    }
                    const dangerousPatterns = SECURITY_CONFIG.patterns.ajax.patterns;
                    return !dangerousPatterns.some(pattern =>
                        new RegExp(pattern).test(decodeURIComponent(url))
                    );
                } catch (error) {
                    console.error('Formtress: Invalid URL:', error);
                    return false;
                }
            };

            const validateHeaders = (headers) => {
                const dangerousHeaders = [
                    'Authorization',
                    'Cookie',
                    'X-CSRF-Token'
                ];

                if (headers instanceof Headers) {
                    headers.forEach((value, key) => {
                        if (dangerousHeaders.includes(key)) {
                            console.warn(`Formtress: Sensitive header detected: ${key}`);
                        }
                    });
                }
                return headers;
            };

            const secureFetch = async (input, init = {}) => {
                const url = input instanceof Request ? input.url : input;

                try {
                    if (!isSecureUrl(url)) {
                        AjaxMonitor.blockRequest('fetch', url, 'Insecure URL');
                        throw new FormtressError('Insecure URL detected', 'ajax');
                    }

                    const requestId = AjaxMonitor.startRequest('fetch', url, init);

                    const secureInit = {
                        ...init,
                        headers: {
                            ...init.headers,
                            'X-Requested-With': 'Formtress',
                            'X-Formtress-Protected': '1'
                        }
                    };

                    try {
                        const response = await originalFetch(input, secureInit);

                        AjaxMonitor.endRequest(requestId,
                            response.ok ? 'success' : 'failed',
                            {
                                status: response.status,
                                statusText: response.statusText,
                                headers: Object.fromEntries(response.headers.entries())
                            }
                        );

                        return response;
                    } catch (error) {
                        AjaxMonitor.endRequest(requestId, 'failed', null, error.message);
                        throw error;
                    }
                } catch (error) {
                    console.error('Formtress: Fetch error:', error);
                    throw error;
                }
            };

            class SecureXMLHttpRequest extends originalXHR {
                constructor() {
                    super();

                    let requestId = null;

                    const originalOpen = this.open;
                    this.open = function(method, url, async = true) {
                        if (!isSecureUrl(url)) {
                            AjaxMonitor.blockRequest('xhr', url, 'Insecure URL');
                            throw new FormtressError('Insecure URL detected', 'ajax');
                        }

                        requestId = AjaxMonitor.startRequest('xhr', url, { method, async });
                        return originalOpen.call(this, method, url, async);
                    };

                    const originalSetHeader = this.setRequestHeader;
                    this.setRequestHeader = function(header, value) {
                        validateHeaders(new Headers([[header, value]]));
                        return originalSetHeader.call(this, header, value);
                    };

                    const originalSend = this.send;
                    this.send = function(data) {
                        this.setRequestHeader('X-Requested-With', 'Formtress');
                        this.setRequestHeader('X-Formtress-Protected', '1');

                        this.addEventListener('readystatechange', () => {
                            if (this.readyState === 4 && requestId) {
                                AjaxMonitor.endRequest(requestId,
                                    this.status >= 200 && this.status < 300 ? 'success' : 'failed',
                                    {
                                        status: this.status,
                                        statusText: this.statusText,
                                        headers: this.getAllResponseHeaders()
                                    }
                                );
                            }
                        });

                        return originalSend.call(this, data);
                    };
                }
            }

            const protectFetch = () => {
                try {
                    // Try to delete existing property first
                    delete window.fetch;

                    Object.defineProperty(window, 'fetch', {
                        configurable: false,
                        enumerable: true,
                        get() {
                            return secureFetch;
                        },
                        set(value) {
                            AjaxMonitor.blockRequest('fetch', 'window.fetch', 'Attempted fetch override');
                            console.warn('Formtress: Attempted to override fetch');
                            return secureFetch;
                        }
                    });

                    Object.freeze(window.fetch);

                    setInterval(() => {
                        if (window.fetch !== secureFetch) {
                            AjaxMonitor.blockRequest('fetch', 'window.fetch', 'Fetch override detected');
                            console.warn('Formtress: Fetch override detected, restoring secure version');
                            try {
                                delete window.fetch;
                                window.fetch = secureFetch;
                            } catch (e) {
                                console.error('Failed to restore fetch:', e);
                            }
                        }
                    }, 1000);
                } catch (e) {
                    console.warn('Could not fully protect fetch:', e);
                    // Fallback: try to at least override the function
                    window.fetch = secureFetch;
                }
            };

            const protectXHR = () => {
                try {
                    delete window.XMLHttpRequest;

                    Object.defineProperty(window, 'XMLHttpRequest', {
                        configurable: false,
                        enumerable: true,
                        get() {
                            return SecureXMLHttpRequest;
                        },
                        set(value) {
                            AjaxMonitor.blockRequest('xhr', 'window.XMLHttpRequest', 'Attempted XHR override');
                            console.warn('Formtress: Attempted to override XMLHttpRequest');
                            return SecureXMLHttpRequest;
                        }
                    });

                    Object.freeze(window.XMLHttpRequest);

                    setInterval(() => {
                        if (window.XMLHttpRequest !== SecureXMLHttpRequest) {
                            AjaxMonitor.blockRequest('xhr', 'window.XMLHttpRequest', 'XHR override detected');
                            console.warn('Formtress: XMLHttpRequest override detected, restoring secure version');
                            try {
                                delete window.XMLHttpRequest;
                                window.XMLHttpRequest = SecureXMLHttpRequest;
                            } catch (e) {
                                console.error('Failed to restore XMLHttpRequest:', e);
                            }
                        }
                    }, 1000);
                } catch (e) {
                    console.warn('Could not fully protect XMLHttpRequest:', e);
                    window.XMLHttpRequest = SecureXMLHttpRequest;
                }
            };

            const protectGlobals = () => {
                const globals = ['self', 'globalThis'];

                globals.forEach(globalName => {
                    const global = window[globalName];
                    if (global && global !== window) {
                        try {
                            delete global.fetch;
                            delete global.XMLHttpRequest;

                            Object.defineProperty(global, 'fetch', {
                                configurable: true,
                                enumerable: true,
                                get() {
                                    return secureFetch;
                                },
                                set(value) {
                                    AjaxMonitor.blockRequest('fetch', `${globalName}.fetch`, 'Attempted fetch override through global');
                                    console.warn(`Formtress: Attempted to override fetch through ${globalName}`);
                                    return secureFetch;
                                }
                            });

                            Object.defineProperty(global, 'XMLHttpRequest', {
                                configurable: true,
                                enumerable: true,
                                get() {
                                    return SecureXMLHttpRequest;
                                },
                                set(value) {
                                    AjaxMonitor.blockRequest('xhr', `${globalName}.XMLHttpRequest`, 'Attempted XHR override through global');
                                    console.warn(`Formtress: Attempted to override XMLHttpRequest through ${globalName}`);
                                    return SecureXMLHttpRequest;
                                }
                            });
                        } catch (e) {
                            console.warn(`Could not protect ${globalName} globals:`, e);
                        }
                    }
                });
            };

            const detectOriginalFetchAccess = () => {
                const warning = () => {
                    AjaxMonitor.blockRequest('fetch', 'originalFetch', 'Attempted access to original fetch');
                    console.warn('Formtress: Attempted to access original fetch detected');
                };

                const monitoredProps = [
                    'constructor',
                    'prototype',
                    '__proto__',
                    'caller',
                    'arguments'
                ];
                const descriptor = {
                    get() {
                        warning();
                        return undefined;
                    },
                    set() {
                        warning();
                        return false;
                    }
                };
                if (!Object.isFrozen(secureFetch)) {
                    monitoredProps.forEach(prop => {
                        try {
                            Object.defineProperty(secureFetch, prop, descriptor);
                        } catch (e) {
                            console.debug(`Formtress: Could not monitor ${prop}`);
                        }
                    });
                }
            };

            return {
                init() {
                    try {
                        protectFetch();
                        protectXHR();
                        protectGlobals();
                        detectOriginalFetchAccess();

                        window.FormtressAjaxMonitor = Object.freeze({
                            getStats: () => AjaxMonitor.getStats(),
                            enableDebug: () => localStorage.setItem('formtress:ajax:debug', 'true'),
                            disableDebug: () => localStorage.setItem('formtress:ajax:debug', 'false'),
                            reset: () => AjaxMonitor.reset(),
                            isSecure: () => {
                                try {
                                    return window.fetch === secureFetch &&
                                        window.XMLHttpRequest === SecureXMLHttpRequest;
                                } catch (e) {
                                    return false;
                                }
                            }
                        });
                        /**
                         * Security check interval
                         * This interval checks if the security is compromised
                         * and if so, it reloads the page
                         */
                        setInterval(() => {
                            if (!FormtressAjaxMonitor.isSecure()) {
                                AjaxMonitor.blockRequest('system', 'security-check', 'Security compromise detected');
                                console.error('Formtress: Security compromise detected, reloading page...');
                                window.location.reload();
                            }
                        }, 2000);
                    } catch (e) {
                        console.error('Failed to initialize SecureAjaxWrapper:', e);
                    }
                }
            };
        })();        
        
        /**
         * Fingerprint methods for browser fingerprinting
         */
        const fingerprintAPI = Object.freeze({
            getViolations: () => {
                if (isDevelopment) {
                    console.log('Getting fingerprint violations');
                }
                return fingerprint.getViolations();
            },
            stop: () => {
                if (isDevelopment) {
                    console.log('Stopping fingerprint monitoring');
                }
                return fingerprint.stop();
            },
            start: () => {
                if (isDevelopment) {
                    console.log('Starting fingerprint monitoring');
                }
                return fingerprint.startMonitoring();
            },
            getCurrentFingerprint: async () => {
                if (isDevelopment) {
                    console.log('Getting current fingerprint');
                }
                return await fingerprint.generateFingerprint();
            }
        });
        if (isDevelopment) {
           window.fingerprintAPI=fingerprintAPI;
        }
        // Initialize secure AJAX wrappers
        SecureAjaxWrapper.init();
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

            /**
             * Fingerprint methods for browser fingerprinting
             */
            fingerprint: fingerprintAPI,
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
})(); // Double IIFE to ensure all code is executed

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

