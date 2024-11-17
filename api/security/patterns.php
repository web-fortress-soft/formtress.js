<?php
header('Content-Type: application/json');
session_start();

// Development mode detection
$isDevelopment = in_array($_SERVER['HTTP_HOST'], ['localhost', '127.0.0.1']);

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: ' . ($isDevelopment ? '*' : $_SERVER['HTTP_ORIGIN']));
    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, X-Formtress-Client');
    header('Access-Control-Allow-Credentials: true');
    exit(0);
}

// Security headers
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');

// Generate CSRF token if it doesn't exist
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// In development, always return the patterns with the CSRF token
if ($isDevelopment) {
    $patterns = loadPatterns();
    echo json_encode([
        'version' => '1.0',
        'timestamp' => time(),
        'csrf_token' => $_SESSION['csrf_token'], // Include token in response
        'patterns' => $patterns
    ]);
    exit;
}

// Production CSRF check
if (!$isDevelopment && $_SERVER['REQUEST_METHOD'] !== 'OPTIONS') {
    $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if ($csrfToken !== $_SESSION['csrf_token']) {
        http_response_code(403);
        echo json_encode([
            'error' => 'Invalid CSRF token',
            'debug' => [
                'received' => $csrfToken,
                'expected' => $_SESSION['csrf_token'],
                'session' => session_id()
            ]
        ]);
        exit;
    }
}

// Load patterns from database or file
function loadPatterns() {
    // You can replace this with database queries
    return [
        'xss' => [
            // Basic XSS patterns
            '<script[^>]*>',
            'javascript:',
            'onerror=',
            'onload=',
            'onclick=',
            'onmouseover=',
            'onfocus=',
            'onblur=',
            'eval\(',
            'document\.cookie',
            'document\.write',
            'innerHTML',
            'fromCharCode',
            'alert\(',
            'String\.fromCharCode',
            '&#x[0-9a-f]+;',
            '&#\d+;',
            'base64',
            '<iframe',
            '<embed',
            '<object',
            '<form',
        ],
        'sql' => [
            // SQL Injection patterns
            'UNION\s+SELECT',
            'SELECT\s+FROM',
            'INSERT\s+INTO',
            'UPDATE\s+\w+\s+SET',
            'DELETE\s+FROM',
            'DROP\s+TABLE',
            'ALTER\s+TABLE',
            '--\s+',
            '#\s*$',
            '\/\*.*\*\/',
            'EXEC\s+xp_',
            'EXEC\s+sp_',
            'WAITFOR\s+DELAY',
            'BENCHMARK\(',
            'SLEEP\(',
        ],
        'command' => [
            // Command Injection patterns
            ';\s*\w+\s*;',
            '\|\s*\w+',
            '`.*`',
            '\$\([^)]+\)',
            '&&\s*\w+',
            '\|\|\s*\w+',
            '>\s*\w+',
            '>>\s*\w+',
            '<\s*\w+',
            '\d+\s*>\s*\w+',
            'chmod\s+[0-7]+',
            'rm\s+-rf',
            'wget\s+http',
            'curl\s+http',
        ]
    ];
}

try {
    $patterns = loadPatterns();
    
    // Add version and timestamp
    $response = [
        'version' => '1.0',
        'timestamp' => time(),
        'patterns' => $patterns
    ];
    
    echo json_encode($response);
} catch (Exception $e) {
    http_response_code(500);
    if (defined('DEBUG') && DEBUG) {
        echo json_encode(['error' => $e->getMessage()]);
    } else {
        echo json_encode(['error' => 'Internal server error']);
    }
}
