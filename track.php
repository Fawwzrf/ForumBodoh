<?php
// Vulnerable tracking pixel endpoint
header('Content-Type: image/gif');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Get tracking parameters (vulnerable - no validation)
$query = $_GET['q'] ?? '';
$ip = $_GET['ip'] ?? '';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$timestamp = date('Y-m-d H:i:s');

// Vulnerable logging - no input sanitization
$trackingData = [
    'timestamp' => $timestamp,
    'query' => $query,
    'ip' => $ip,
    'user_agent' => $userAgent,
    'referer' => $referer,
    'cookies' => $_COOKIE,
    'session' => session_id(),
    'additional_params' => $_GET
];

// Create logs directory if it doesn't exist
if (!file_exists('logs')) {
    mkdir('logs', 0777, true);
}

// Vulnerable file writing - could be used for log injection
$logEntry = json_encode($trackingData) . "\n";
file_put_contents('logs/tracking.log', $logEntry, FILE_APPEND | LOCK_EX);

// Also log to a "hidden" location that might be web-accessible
file_put_contents('assets/css/tracking_data.css.log', $logEntry, FILE_APPEND | LOCK_EX);

// Set tracking cookies (vulnerable - no HttpOnly, Secure flags)
setcookie('track_query', base64_encode($query), time() + 3600, '/');
setcookie('track_session', uniqid(), time() + 86400, '/');

// If there's a callback parameter, create a JSONP response (vulnerable to XSS)
if (isset($_GET['callback'])) {
    header('Content-Type: application/javascript');
    $callback = $_GET['callback'];
    // Vulnerable: Direct output without validation
    echo $callback . '(' . json_encode($trackingData) . ');';
    exit;
}

// Return a 1x1 transparent GIF
$gif = base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
echo $gif;
exit;
