<?php
header('Content-Type: application/json');
session_start();

// Security headers
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');

// CSRF protection
if (!isset($_SERVER['HTTP_X_CSRF_TOKEN']) || $_SERVER['HTTP_X_CSRF_TOKEN'] !== $_SESSION['csrf_token']) {
    http_response_code(403);
    echo json_encode(['error' => 'Invalid CSRF token']);
    exit;
}

// Validate request method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

if (!$input || !isset($input['value']) || !isset($input['type'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid input']);
    exit;
}

// Load patterns for the specified type
function getPatterns($type) {
    $patterns = require __DIR__ . '/patterns.php';
    return $patterns[$type] ?? [];
}

try {
    $value = $input['value'];
    $type = $input['type'];
    $patterns = getPatterns($type);
    $matches = [];
    
    foreach ($patterns as $pattern) {
        if (preg_match("/$pattern/i", $value)) {
            $matches[] = $pattern;
        }
    }
    
    echo json_encode([
        'isValid' => empty($matches),
        'matches' => $matches,
        'type' => $type,
        'timestamp' => time()
    ]);
} catch (Exception $e) {
    http_response_code(500);
    if (defined('DEBUG') && DEBUG) {
        echo json_encode(['error' => $e->getMessage()]);
    } else {
        echo json_encode(['error' => 'Internal server error']);
    }
} 