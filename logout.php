<?php
session_start();

// Simple logout - no CSRF protection
if (isset($_SESSION['user_id'])) {
    // Update last activity before logout
    if (file_exists('config/database.php')) {
        require_once 'config/database.php';
        require_once 'includes/functions.php';
        updateLastActivity($_SESSION['user_id']);
    }

    // Clear session
    session_destroy();

    // Redirect with message (vulnerable to XSS)
    $message = $_GET['msg'] ?? 'Anda telah berhasil logout.';
    header("Location: index.php?msg=" . urlencode($message));
} else {
    header('Location: index.php');
}
exit;
