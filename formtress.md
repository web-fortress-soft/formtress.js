# Formtress.js

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Size](https://img.shields.io/badge/size-28.4kB-yellow.svg)

Formtress.js is an enterprise-grade form security and validation framework that provides comprehensive protection against common web vulnerabilities while maintaining excellent user experience and accessibility.

## Features

- 🛡️ **Advanced Security**
  - XSS Protection
  - SQL Injection Prevention
  - CSRF Protection
  - Prototype Pollution Prevention
  - Path Traversal Detection

- 🔍 **Input Validation**
  - Built-in validators
  - Custom validation rules
  - Real-time validation
  - Async validation support

- 🚦 **Rate Limiting**
  - Configurable timeframes
  - Custom thresholds
  - Per-form and per-field limiting

- ♿ **Accessibility**
  - ARIA attributes
  - Screen reader friendly
  - Keyboard navigation support
  - Customizable feedback

- 🎨 **Customization**
  - Extensive configuration options
  - Custom styling
  - Event hooks
  - Custom validators

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Basic Usage](#basic-usage)
4. [Advanced Usage](#advanced-usage)
5. [Configuration](#configuration)
6. [Security Features](#security-features)
7. [Validation](#validation)
8. [Events](#events)
9. [Accessibility](#accessibility)
10. [Best Practices](#best-practices)
11. [API Reference](#api-reference)
12. [Browser Support](#browser-support)
13. [Contributing](#contributing)
14. [License](#license)

## Installation

```bash
npm install formtress
# or
yarn add formtress
# or
pnpm add formtress
```

Or include via CDN:

```html
<script src="https://cdn.jsdelivr.net/npm/formtress@2.0.0/dist/formtress.min.js"></script>
```

## Quick Start

```html
<form id="myForm">
  <input type="email" name="email" required>
  <input type="password" name="password" required>
  <button type="submit">Submit</button>
</form>

<script>
  const form = Formtress.secure('myForm');
</script>
```

## Basic Usage

### Automatic Form Protection

Formtress automatically secures all forms on your page:

```html
<form id="signupForm">
  <input type="text" name="username" required>
  <input type="email" name="email" required>
  <input type="password" name="password" required>
  <button type="submit">Sign Up</button>
</form>
```

### Manual Initialization

```javascript
// Select by ID
const form1 = Formtress.secure('signupForm');

// Select by element
const formElement = document.querySelector('#signupForm');
const form2 = Formtress.secure(formElement);
```

### Event Handling

```javascript
document.getElementById('signupForm').addEventListener('formtress:success', (e) => {
  const sanitizedData = e.detail.data;
  console.log('Clean data:', sanitizedData);
});
```

## Advanced Usage

### Custom Configuration

```javascript
const form = Formtress.secure('myForm', {
  security: {
    patterns: {
      xss: {
        enabled: true,
        patterns: [
          /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
          // Add custom patterns
        ]
      }
    }
  },
  validation: {
    customEmail: {
      pattern: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/,
      message: 'Please enter a valid email address'
    }
  },
  feedback: {
    showSuccess: true,
    successColor: '#28a745',
    errorColor: '#dc3545'
  }
});
```

### Custom Validation Rules

```javascript
const form = Formtress.secure('myForm', {
  hooks: {
    beforeValidation: async (field, value) => {
      if (field.name === 'username') {
        const isAvailable = await checkUsernameAvailability(value);
        if (!isAvailable) {
          throw new Error('Username already taken');
        }
      }
    }
  }
});
```

### CSRF Protection

```javascript
// Server-side token generation (example)
app.get('/form', (req, res) => {
  const csrfToken = generateSecureToken();
  res.render('form', { csrfToken });
});

// Client-side implementation
const form = Formtress.secure('myForm', {
  csrf: {
    enabled: true,
    fieldName: '_csrf',
    validateOnSubmit: true
  }
});
```

## Configuration

### Default Configuration

```javascript
const defaultConfig = {
  security: {
    patterns: {
      xss: { enabled: true },
      sql: { enabled: true },
      prototype: { enabled: true },
      path: { enabled: true },
      command: { enabled: true }
    }
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
    errorColor: '#ff4444'
  },
  accessibility: {
    ariaLive: 'polite',
    useAriaInvalid: true,
    useAriaDescribedBy: true
  }
};
```

### Runtime Configuration Updates

```javascript
const form = Formtress.secure('myForm');

// Update config
form.updateConfig({
  feedback: {
    showSuccess: false
  }
});

// Get current config
const currentConfig = form.getConfig();
```

## Security Features

### XSS Protection

```javascript
const form = Formtress.secure('myForm', {
  security: {
    patterns: {
      xss: {
        enabled: true,
        patterns: [
          /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
          /javascript:/gi,
          // Additional patterns
        ]
      }
    }
  }
});
```

### Rate Limiting

```javascript
const form = Formtress.secure('myForm', {
  rateLimit: {
    enabled: true,
    window: 1000,    // Time window in ms
    max: 30,         // Max attempts in window
    windowMs: 60000  // Overall window
  }
});
```
### Global configuration when initializing:

```javascript
const form = Formtress.secure('myForm', {
  security: {
    patterns: {
      xss: { enabled: true },
      sql: { enabled: true },
      prototype: { enabled: true },
      path: { enabled: true },
      command: { enabled: true }
    }
  },
    feedback: {
        showSuccess: false, // Hide success messages
        errorColor: '#FF0000', // Custom error color
        customStyles: {
            fontWeight: 'bold',
            padding: '5px'
        }
    },
});
```

## Best Practices

### 1. Security

```javascript
// Enable all security features
const form = Formtress.secure('myForm', {
  security: {
    patterns: {
      xss: { enabled: true },
      sql: { enabled: true },
      prototype: { enabled: true },
      path: { enabled: true },
      command: { enabled: true }
    }
  },
  csrf: {
    enabled: true
  }
});

// Always validate server-side
form.addEventListener('formtress:success', async (e) => {
  const response = await fetch('/api/submit', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(e.detail.data)
  });
});
```

### 2. Error Handling

```javascript
const form = Formtress.secure('myForm', {
  hooks: {
    onError: (error) => {
      // Log errors
      console.error('Form Error:', error);
      
      // Show user-friendly message
      showUserError(error.message);
      
      // Track errors
      analytics.trackError(error);
    }
  }
});
```

### 3. Accessibility

```javascript
const form = Formtress.secure('myForm', {
  accessibility: {
    ariaLive: 'polite',
    useAriaInvalid: true,
    useAriaDescribedBy: true
  },
  feedback: {
    customStyles: {
      fontSize: '1rem',
      padding: '0.5rem',
      marginTop: '0.25rem'
    }
  }
});
```

### 4. Performance

```javascript
// Debounce validation
const form = Formtress.secure('myForm', {
  validation: {
    debounce: 300,  // ms
    async: true
  }
});

// Optimize rate limiting
form.updateConfig({
  rateLimit: {
    window: 2000,    // Increase window
    max: 50,         // Allow more attempts
    windowMs: 120000 // Longer overall window

  }
});
```
### 5. Hooks
```javascript

const form = Formtress.secure('myForm', {
  hooks: {
    beforeSubmit: (field, value) => {
      console.log('Before validation:', field.name, value);
        // Custom validation
        const value = event.target.elements.email.value;
        if (!value.endsWith('@company.com')) {
            throw new Error('Must use company email');
        }
    },
     beforeValidation: (field, validateOnSubmit) => {
      console.log('Before validation:', field.name, validateOnSubmit);
     },
     afterValidation: (field, value) => {
      console.log('After validation:', field.name, value);
     },
     afterSubmit: (data) => {    
      console.log('After submit:', data);
     },
     onError: (error) => {
      console.error('Form Error:', error);
     }
  }
});
```
## Security Levels and Recommendations

### Default Security Configuration Rating

| Protection Type | Default Level | Rating | Description |
|----------------|---------------|---------|-------------|
| XSS Protection | Strict | ⭐⭐⭐⭐⭐ | Full protection against common XSS patterns including scripts, event handlers, data URIs, and eval |
| SQL Injection | High | ⭐⭐⭐⭐ | Blocks common SQL commands and patterns, suitable for most applications |
| CSRF Protection | Optional | ⭐⭐⭐ | Requires manual token setup, but provides robust protection when enabled |
| Prototype Pollution | High | ⭐⭐⭐⭐ | Blocks common prototype chain attacks and unsafe object modifications |
| Path Traversal | High | ⭐⭐⭐⭐ | Prevents directory traversal attempts and common path manipulation |
| Command Injection | High | ⭐⭐⭐⭐ | Blocks shell command execution patterns and dangerous system calls |
| Rate Limiting | Moderate | ⭐⭐⭐ | Default 30 requests per minute, adjustable based on needs |

### Security Level Recommendations

#### Minimal Security (Basic Websites)
```javascript
const form = Formtress.secure('myForm', {
  security: {
    patterns: {
      xss: { enabled: true },
      sql: { enabled: true },
      prototype: { enabled: false },
      path: { enabled: false },
      command: { enabled: false }
    }
  },
  rateLimit: {
    enabled: false
  }
});
```

#### Standard Security (Most Applications)
```javascript
const form = Formtress.secure('myForm', {
  security: {
    patterns: {
      xss: { enabled: true },
      sql: { enabled: true },
      prototype: { enabled: true },
      path: { enabled: true },
      command: { enabled: true }
    }
  },
  rateLimit: {
    enabled: true,
    window: 1000,
    max: 30,
    windowMs: 60000
  }
});
```

#### Maximum Security (Financial/Healthcare)
```javascript
const form = Formtress.secure('myForm', {
  security: {
    patterns: {
      xss: { 
        enabled: true,
        patterns: [
          ...DEFAULT_PATTERNS.xss,
          /data:/gi,  // Additional data URI protection
          /blob:/gi,  // Block blob URLs
          /<\s*link/gi, // Block dynamic stylesheet injection
          /<\s*meta/gi  // Block meta tag injection
        ]
      },
      sql: { 
        enabled: true,
        patterns: [
          ...DEFAULT_PATTERNS.sql,
          /WAITFOR\s+DELAY/gi,  // Prevent time-based attacks
          /BENCHMARK\(/gi       // Prevent benchmark attacks
        ]
      },
      prototype: { enabled: true },
      path: { enabled: true },
      command: { enabled: true }
    }
  },
  csrf: {
    enabled: true,
    validateOnSubmit: true,
    regenerateOnValidation: true
  },
  rateLimit: {
    enabled: true,
    window: 500,     // Stricter rate limiting
    max: 10,         // Lower threshold
    windowMs: 30000  // Shorter window
  },
  validation: {
    debounce: 200,   // Faster validation response
    async: true
  }
});
```

### Security Best Practices

1. **Always Enable CSRF for Forms Handling Sensitive Data**
```javascript
{
  csrf: {
    enabled: true,
    fieldName: '_csrf',
    validateOnSubmit: true
  }
}
```

2. **Customize Rate Limiting Based on Application Type**
```javascript
// High-traffic applications
{
  rateLimit: {
    enabled: true,
    window: 2000,    // Longer window
    max: 50,         // Higher threshold
    windowMs: 120000 // 2-minute window
  }
}

// Security-critical applications
{
  rateLimit: {
    enabled: true,
    window: 500,     // Short window
    max: 5,          // Low threshold
    windowMs: 30000  // 30-second window
  }
}
```

3. **Additional Security Headers (Server-side Recommendation)**
```javascript
// Add these headers server-side
{
  'Content-Security-Policy': "default-src 'self'",
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=()'
}
```

4. **Real-time Validation with Error Tracking**
```javascript
const form = Formtress.secure('myForm', {
  hooks: {
    beforeValidation: async (field, value) => {
      // Log validation attempts
      analytics.trackValidation(field.name);
    },
    onError: (error) => {
      // Track security violations
      securityMonitor.reportViolation({
        type: error.type,
        field: error.field,
        timestamp: new Date()
      });
    }
  }
});
```

5. **Compliance Mode for Regulated Industries**
```javascript
const form = Formtress.secure('myForm', {
  security: {
    compliance: {
      mode: 'strict',      // 'strict' | 'standard' | 'relaxed'
      logging: true,       // Enable security logging
      alerting: true,      // Enable security alerts
      auditTrail: true    // Keep validation history
    }
  }
});
```

### Security Level Testing

```javascript
// Test current security configuration
const securityTest = await Formtress.testSecurity('myForm', {
  level: 'maximum',  // 'maximum' | 'standard' | 'minimal'
  tests: ['xss', 'sql', 'csrf', 'prototype', 'path', 'command']
});

console.log(securityTest.results);  // View test results
console.log(securityTest.recommendations);  // View security recommendations
```

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- IE11 (with polyfills)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

---

For more information, visit our [documentation](https://formtress.js.org) or [GitHub repository](https://github.com/formtress/formtress).