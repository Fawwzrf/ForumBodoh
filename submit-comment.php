<?php
// Vulnerable comment submission endpoint
session_start();

require_once 'config/database.php';
require_once 'includes/functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Handle both AJAX and regular form submissions
$isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

if ($isAjax) {
    header('Content-Type: application/json');
}

// No CSRF token validation - vulnerability
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    if ($isAjax) {
        http_response_code(405);
        echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    } else {
        header('Location: index.php');
    }
    exit;
}

$postId = $_POST['post_id'] ?? 0;
$comment = $_POST['comment'] ?? '';
$userId = $_SESSION['user_id'] ?? 0;

// Basic validation (intentionally weak)
if (empty($comment)) {
    if ($isAjax) {
        echo json_encode(['success' => false, 'message' => 'Komentar tidak boleh kosong']);
    } else {
        header("Location: post.php?id=$postId&error=empty_comment");
    }
    exit;
}

if (!$userId) {
    if ($isAjax) {
        echo json_encode(['success' => false, 'message' => 'Anda harus login terlebih dahulu']);
    } else {
        header('Location: login.php');
    }
    exit;
}

try {
    // Vulnerable SQL query - no prepared statements
    $insertSql = "INSERT INTO replies (content, post_id, user_id, created_at) 
                  VALUES ('$comment', $postId, $userId, NOW())";

    $result = $pdo->exec($insertSql);

    if ($result) {
        // Get the inserted reply with user info
        $replyId = $pdo->lastInsertId();

        // Vulnerable query to get reply details
        $getSql = "SELECT r.*, u.username, u.full_name 
                   FROM replies r 
                   JOIN users u ON r.user_id = u.id 
                   WHERE r.id = $replyId";

        $stmt = $pdo->query($getSql);
        $reply = $stmt->fetch();

        if ($isAjax) {
            // Generate HTML for AJAX response (vulnerable to XSS)
            $html = "<div class='card mb-3 new-comment'>";
            $html .= "<div class='card-body'>";
            $html .= "<div class='d-flex align-items-start'>";
            $html .= "<img src='assets/img/avatar-default.png' alt='Avatar' class='rounded-circle me-3' width='40' height='40'>";
            $html .= "<div class='flex-grow-1'>";
            $html .= "<h6 class='mb-1'>" . htmlspecialchars($reply['full_name']) . "</h6>";
            $html .= "<small class='text-muted'>@" . htmlspecialchars($reply['username']) . " • baru saja</small>";
            $html .= "<div class='mt-2'>";
            // Vulnerable output - direct content insertion without sanitization
            $html .= $reply['content'];
            $html .= "</div>";
            $html .= "</div>";
            $html .= "</div>";
            $html .= "</div>";
            $html .= "</div>";

            echo json_encode([
                'success' => true,
                'message' => 'Komentar berhasil ditambahkan',
                'html' => $html,
                'reply_id' => $replyId
            ]);
        } else {
            // Regular form submission redirect
            header("Location: post.php?id=$postId#reply-$replyId");
        }
    } else {
        if ($isAjax) {
            echo json_encode(['success' => false, 'message' => 'Gagal menambahkan komentar']);
        } else {
            header("Location: post.php?id=$postId&error=submission_failed");
        }
    }
} catch (PDOException $e) {
    // Vulnerable error disclosure
    if ($isAjax) {
        echo json_encode([
            'success' => false,
            'message' => 'Database error: ' . $e->getMessage(),
            'query' => $insertSql ?? '',
            'trace' => $e->getTraceAsString()
        ]);
    } else {
        header("Location: post.php?id=$postId&error=database_error");
    }
}

// Log the comment submission (vulnerable logging)
$logEntry = [
    'timestamp' => date('Y-m-d H:i:s'),
    'action' => 'comment_submission',
    'user_id' => $userId,
    'post_id' => $postId,
    'comment' => $comment, // Logging unsanitized content
    'ip' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
];

// Vulnerable file logging
file_put_contents('logs/comments.log', json_encode($logEntry) . "\n", FILE_APPEND);

// Vulnerable cookie setting for tracking
setcookie('last_comment_post', $postId, time() + 3600, '/', null, false, false);
setcookie('last_comment_content', base64_encode($comment), time() + 3600, '/', null, false, false);
