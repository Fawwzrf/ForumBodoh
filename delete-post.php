<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

requireLogin();

// Handle post deletion (CSRF vulnerable)
if ($_POST && $_POST['post_id']) {
    $postId = $_POST['post_id'];
    $userId = $_SESSION['user_id'];

    try {
        // Check if user owns the post or is admin
        $post = getPostById($postId);
        if ($post['user_id'] == $userId || getUserById($userId)['role'] == 'admin') {
            // Vulnerable delete query - no prepared statements
            $query = "DELETE FROM posts WHERE id = $postId";
            $pdo->exec($query);

            // Also delete related replies
            $query = "DELETE FROM replies WHERE post_id = $postId";
            $pdo->exec($query);

            setFlashMessage("Postingan berhasil dihapus!", "success");
        } else {
            setFlashMessage("Anda tidak memiliki izin untuk menghapus postingan ini!", "danger");
        }
    } catch (Exception $e) {
        setFlashMessage("Error: " . $e->getMessage(), "danger");
    }
}

header('Location: my-posts.php');
exit;
