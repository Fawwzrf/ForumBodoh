<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// API endpoint untuk statistik admin (vulnerable)
header('Content-Type: application/json');

// No authentication check - vulnerability
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'stats':
        echo json_encode([
            'users' => getTotalUsers(),
            'posts' => getTotalPosts(),
            'categories' => getTotalCategories(),
            'today_posts' => getTodayPosts(),
            'timestamp' => date('Y-m-d H:i:s')
        ]);
        break;

    case 'search':
        // Vulnerable search API
        $query = $_GET['q'] ?? '';
        $results = searchPosts($query);
        echo json_encode(['results' => $results]);
        break;

    case 'user_info':
        // Information disclosure vulnerability
        $userId = $_GET['user_id'] ?? 0;
        $user = getUserById($userId);
        // Exposing sensitive information
        echo json_encode([
            'user' => $user,
            'session_id' => session_id(),
            'server_info' => $_SERVER
        ]);
        break;

    case 'logs':
        // Vulnerable log access
        $logType = $_GET['type'] ?? 'access';
        $logFile = "logs/{$logType}.log";

        if (file_exists($logFile)) {
            $logs = file_get_contents($logFile);
            echo json_encode(['logs' => $logs]);
        } else {
            echo json_encode(['error' => 'Log file not found']);
        }
        break;

    default:
        echo json_encode(['error' => 'Invalid action']);
}
