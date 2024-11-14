# Formtress.js 🛡️

> Military-grade form and DOM security with focus on DX.
<br />

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/yourusername/formtress)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

## It's not your choice which security vulnerability to address. Your only option is ALL.

Formtress.js is an advanced, enterprise-grade, unobtrusive, security-focused form utility library that automatically protects your forms and DOM against common and advanced web vulnerabilities. It provides comprehensive security features on its default state, while maintaining full flexibility for customization. It includes self-defense mechanisms to prevent security level degradation, prototyping and instance access.

## Features 🚀

- **Self-Healing Security Architecture**
  - Runtime method interception and protection
  - Continuous security state monitoring
  - Automatic recovery from compromises
  - Real-time security violation detection
  - Multi-layer property protection

- **Advanced AJAX Protection**
  - Secure `fetch` and `XMLHttpRequest` wrappers
  - Request monitoring and statistics
  - Cross-origin request validation
  - Security headers injection
  - Request signature verification

- **Comprehensive Security**
  - XSS (Cross-Site Scripting) Protection
  - SQL Injection Prevention
  - CSRF (Cross-Site Request Forgery) Protection
  - Prototype Pollution Prevention
  - Path Traversal Detection
  - Command Injection Prevention
  - CSP Support

- **Remote Configuration System**
  - Secure configuration loading
  - Cryptographic signature verification
  - Configuration integrity validation
  - Fallback mechanisms
  - Auto-configuration support

- **Enterprise Features**
  - Real-time security monitoring
  - Event-based violation reporting
  - Audit trail creation
  - Rate limiting
  - Accessibility support (ARIA)

## Installation 📦

```bash
npm install formtress
```

Or include it directly in your HTML:
```html
<script src="https://cdn.jsdelivr.net/npm/formtress@0.1.0/dist/formtress.min.js"></script>
```

## Quick Start 🚀

Basic usage with auto-configuration:

```html
<script src="formtress.js"></script>
<script>
    // Formtress automatically protects all forms
    // No configuration needed for basic protection
</script>
```

## Advanced Configuration 🔧

### Remote Configuration

```javascript
// Load and apply remote configuration
await Formtress.loadConfig('/api/formtress/config', {
    validateSignature: true,
    publicKey: 'YOUR_PUBLIC_KEY',
    retries: 3,
    timeout: 5000
});
```

### Manual Configuration

```javascript
Formtress.inject('#myForm', {
    security: {
        ajax: {
            enabled: true,
            validateOrigin: true,
            allowedDomains: ['trusted-domain.com']
        },
        monitoring: {
            enabled: true,
            reportUrl: '/api/security/violations'
        }
    }
});
```

## Security Monitoring 🔍

Monitor security events in real-time:

```javascript
// Listen for security violations
document.addEventListener('formtress:ajax:request:blocked', (e) => {
    console.warn('Security violation:', e.detail);
});

// Get security statistics
const stats = FormtressAjaxMonitor.getStats();
console.log('Security Stats:', stats);

// Enable debug mode
FormtressAjaxMonitor.enableDebug();
```

## Self-Healing Features 🔄

Formtress includes automatic recovery mechanisms:

- Runtime security state monitoring
- Automatic restoration of compromised protections
- Real-time violation detection and response
- Security level degradation prevention

## Browser Support 🌐

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- IE11+ (with polyfills)

## Contributing 🤝

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## Security 🔒

Found a security issue? Please email web-formtress-sort@gmail.com or submit it through our bug bounty program.

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by Resti Guay

Remember, security isn't a feature - it's a necessity.
