# Formtress.js 🛡️

## It's not your choice which security vulnerability to address. We got you covered.
<br />

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/yourusername/formtress)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)



> Enterprise-grade form security made simple.

formtress.js is an advanced, enterprise-grade, unobtrusive, security-focused, multi-layer form utility library that automatically protects your forms against common and advanced web vulnerabilities. It provides comprehensive security features on its default state, while maintaining full flexibility for customization. It also includes self defense mechanisms to prevent security level degradation, prototyping and instance access.

## Features 🚀

- **Automatic Form Discovery & Protection**
  - No manual initialization required
  - Secure by default
  - Non-intrusive implementation
  - Supports dynamic form and input creation

- **Comprehensive Security**
  - XSS (Cross-Site Scripting) Protection
  - SQL Injection Prevention
  - CSRF (Cross-Site Request Forgery) Protection
  - Prototype Pollution Prevention
  - Path Traversal Detection
  - Command Injection Prevention

- **Advanced Input Validation & Sanitization**
  - Real-time validation
  - Configurable sanitization rules
  - Built-in patterns for common fields (email, phone, URL, etc.)
  - Custom validation support

- **Enterprise Features**
  - Rate limiting
  - Event monitoring
  - Robust error handling
  - Accessibility support (ARIA)
  - Configuration validation
  - Deep merge utility
  - Secure configuration store

- **Self Defense Mechanisms - because security must be secured**
  - Security configuration schema
  - Security level degradation detection and prevention
  - Prevent prototype pollution
  - Prevent property tampering
  - Prevent property deletion
  - Prevent property enumeration
  - Prevent property redefinition
  - Prevent property overwriting
  - Prevent property tampering
  - Prevent property deletion
 

## Installation 📦
- To be published on npm soon
```bash
npm install formtress
```

Or include it directly in your HTML:
- To be published on jsdelivr soon
```html
<script src="https://cdn.jsdelivr.net/npm/formtress@0.1.0/dist/formtress.min.js"></script>
```

## Quick Start 🚀

Formtress.js works automatically! Just include it in your project:

```html
<script src="formtress.js"></script>
```

That's it! Your forms are now protected. Formtress automatically:
- Discovers and secures all forms
- Validates inputs in real-time
- Prevents XSS and injection attacks
- Provides feedback to users

## Advanced Usage 🔧

### Custom Configuration

```javascript
Formtress.inject('#myForm', {
  security: {
    rateLimit: {
      enabled: true,
      window: 1000,
      max: 30
    },
    csrf: {
      enabled: true,
      fieldName: '_csrf'
    }
  },
  feedback: {
    showSuccess: true,
    showError: true,
    successColor: '#4CAF50',
    errorColor: '#ff4444'
  }
});
```

### DOM Protection

```javascript
// Protect specific elements
Formtress.dom.protectElement(element, {
  allowHtml: false,
  allowUrls: true,
  urlWhitelist: ['trusted-domain.com']
});

// Sanitize content
const sanitized = Formtress.dom.sanitize(userInput);
```

### Content Sanitization

```javascript
const sanitizer = Formtress.dom.createSanitizer({
  mode: 'strict',
  allowedProtocols: ['http:', 'https:'],
  allowedDomains: ['trusted.com']
});

const clean = sanitizer.sanitizeContent(userContent);
```

## Security Features Deep Dive 🔐

### XSS Prevention
- Automatic escaping of dangerous characters
- Pattern-based detection of malicious scripts
- Safe HTML handling

### SQL Injection Prevention
- Detection of SQL keywords and patterns
- Validation of input against SQL injection attempts
- Sanitization of database-bound inputs

### CSRF Protection
- Automatic token generation and validation
- Configurable token placement
- Request validation

### Rate Limiting
- Configurable time windows
- Request counting and throttling
- Protection against brute force attacks

## Events & Hooks 🎣

```javascript
form.addEventListener('formtress:violation', (e) => {
  console.log('Security violation:', e.detail);
});

form.addEventListener('formtress:success', (e) => {
  console.log('Form validated:', e.detail.data);
});
```

## Accessibility ♿

Formtress.js is built with accessibility in mind:
- ARIA attributes support
- Screen reader friendly error messages
- Keyboard navigation support
- Color contrast compliance

## Browser Support 🌐

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- IE11+ (with polyfills)

## Contributing 🤝

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security 🔒

Found a security issue? Please email web-formtress-sort@gmail.com or submit it through our bug bounty program.

---

Made with ❤️ by Resti Guay

Remember, security isn't a feature - it's a necessity.
