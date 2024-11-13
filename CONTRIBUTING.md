# Contributing to Formtress.js

🎉 First off, thanks for taking the time to contribute! 🎉

The following is a set of guidelines for contributing to Formtress.js. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [What Should I Know Before Getting Started?](#what-should-i-know-before-getting-started)
- [Security First Development](#security-first-development)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Workflow](#development-workflow)
- [Style Guidelines](#style-guidelines)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security Guidelines](#security-guidelines)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [maintainers@yourdomain.com].

## What Should I Know Before Getting Started?

### Project Philosophy

Formtress.js is built on these core principles:

1. **Security First**: Every feature must be implemented with security as the primary concern
2. **Unobtrusive**: The library should work seamlessly without requiring significant changes to existing code
3. **Performance**: Security features should not significantly impact form performance
4. **Accessibility**: All features must maintain or enhance accessibility
5. **Reliability**: Code must be thoroughly tested and reliable

### Technology Stack

- Pure JavaScript (ES6+)
- No external dependencies
- Jest for testing
- ESLint for code quality
- WebdriverIO for E2E testing

## Security First Development

When contributing to Formtress.js, always keep security at the forefront:

### Security Checklist

- [ ] Input validation is strict and comprehensive
- [ ] Output is properly escaped
- [ ] No eval() or new Function() usage
- [ ] No DOM-based XSS vulnerabilities
- [ ] No prototype pollution possibilities
- [ ] Proper error handling without information leakage
- [ ] Rate limiting considerations
- [ ] CSRF protection intact
- [ ] Safe DOM manipulation

## How Can I Contribute?

### Reporting Bugs

- **Use the latest version** before reporting
- **Check existing issues** to avoid duplicates
- **Provide detailed information** including:
  - Version of Formtress.js
  - Browser and version
  - Minimal reproduction code
  - Expected vs actual behavior
  - Console errors (if any)

### Suggesting Enhancements

Create an issue using the feature request template, including:
- Clear use case description
- Security implications consideration
- Implementation suggestions
- Performance impact analysis

### Code Contributions

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Write and test your code
4. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
5. Push to the branch (`git push origin feature/AmazingFeature`)
6. Open a Pull Request

## Development Workflow

1. **Setup Development Environment**
```bash
git clone https://github.com/yourusername/formtress.js.git
cd formtress.js
npm install
```

2. **Run Tests**
```bash
npm test                 # Run unit tests
npm run test:e2e        # Run end-to-end tests
npm run test:security   # Run security tests
```

3. **Build**
```bash
npm run build           # Production build
npm run build:dev      # Development build
```

4. **Lint**
```bash
npm run lint           # Check code style
npm run lint:fix       # Fix code style issues
```

## Style Guidelines

### JavaScript Style Guide

We use ESLint with a custom configuration:

- ES6+ features encouraged
- 2 spaces for indentation
- Semicolons required
- Single quotes for strings
- No unused variables
- Maximum line length of 100 characters

### Documentation Style

- Use JSDoc for all public methods
- Include security considerations in documentation
- Add examples for complex features
- Document security implications

### Testing Guidelines

- Write unit tests for all new features
- Include security-focused test cases
- Test edge cases thoroughly
- Add integration tests for complex features
- Maintain 90%+ code coverage

## Commit Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security improvement
- `docs`: Documentation only changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

## Pull Request Process

1. **Before Submitting**
   - Update documentation
   - Add/update tests
   - Run full test suite
   - Update changelog
   - Verify security implications

2. **PR Template**
   - Clear description of changes
   - Security impact analysis
   - Breaking changes notification
   - Screenshots/recordings (if applicable)
   - Testing procedures

3. **Review Process**
   - Two maintainer approvals required
   - Security review for security-related changes
   - CI checks must pass
   - Documentation review

4. **After Merge**
   - Delete your branch
   - Update related issues
   - Monitor CI/CD pipeline

## Security Guidelines

### Security Review Checklist

- [ ] Validate all inputs
- [ ] Sanitize all outputs
- [ ] Check for XSS vulnerabilities
- [ ] Verify CSRF protection
- [ ] Review rate limiting
- [ ] Check error handling
- [ ] Validate configurations
- [ ] Review DOM manipulation
- [ ] Check for prototype pollution
- [ ] Verify safe dependencies

### Reporting Security Issues

For security issues, please email security@yourdomain.com instead of creating a public issue. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Questions?

Feel free to reach out to the maintainers or create a discussion in the GitHub repository.

---

Thank you for contributing to making web forms more secure! 🚀