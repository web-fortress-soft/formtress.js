<?php
header('Content-Type: application/json');
session_start();

// Generate new CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

echo json_encode([
    'token' => $_SESSION['csrf_token'],
    'timestamp' => time()
]); 