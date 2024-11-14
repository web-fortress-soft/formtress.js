/**
 * Formtress.js - Enterprise Form Security Library
 * Because security starts with the form.
 * @author: Resti Guay
 * Version: 0.1.0
 * Features:
 * - Automatic form discovery and protection
 * - Grade A security
 * - XSS, SQL Injection, CSRF, CSP, PHP, Python, Ruby, Java, C#, Shell, Command, Prototype, Path, protection
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
 * - Configuration Auto-Discovery
 * - Tampered Configuration Denial
 * - Debugger Trap
 * - Performance Trap
 * - DevTools Detection
 * - Exhaustive Error Handling
 * - Security check interval
 * - Fetch and XHR override protection
 * - CSP and CORS protection
 * - Secure configuration loading
 * - Remote configuration loading
 * - Configuration Signature Validation 
 */
(function() {    
const Formtress = (() => {
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
            validateOnSubmit: true
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

    // Core security class
    class SecurityCore {
        constructor(config) {
            this.violations = [];
            this.config = deepMerge(SECURITY_CONFIG, config);
            this.patterns = this.cloneSecurityPatterns(SECURITY_CONFIG.patterns);
            
            // Initialize CSRF settings
            this.initializeCsrf(config?.csrf);
        }

        /**
         * Initialize CSRF settings and detect existing tokens
         * @param {Object} csrfConfig - CSRF configuration
         */
        initializeCsrf(csrfConfig = {}) {
            this.csrfEnabled = csrfConfig?.enabled ?? false;
            this.csrfFieldName = csrfConfig?.fieldName ?? '_csrf';
            
            // If CSRF is enabled but no field exists, we'll add one during form initialization
            this.csrfDetected = false;
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

            // Check for other common CSRF field names
            const commonCsrfNames = [
                '_csrf',
                'csrf_token',
                'csrf-token',
                'csrfToken',
                'csrfmiddlewaretoken', // Django
                '_token',             // Laravel
                '__RequestVerificationToken' // ASP.NET
            ];

            for (const name of commonCsrfNames) {
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
                    console.error('Formtress: Configuration error detected');
                    window.location.reload();
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
     * Debounce a function
     * @param {function} func - The function to debounce
     * @param {number} wait - The wait time in milliseconds
     * @returns {function} The debounced function
     */
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

            monitoredProps.forEach(prop => {
                try {
                    Object.defineProperty(secureFetch, prop, {
                        get() {
                            warning();
                            return undefined;
                        },
                        set() {
                            warning();
                            return false;
                        },
                        configurable: false
                    });
                } catch (e) {
                    // Some properties might not be configurable
                    console.debug(`Formtress: Could not monitor ${prop}`, e);
                }
            });
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

    // Add to the Formtress initialization (inside the IIFE):
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