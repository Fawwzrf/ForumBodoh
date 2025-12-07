<?php
// Vulnerable AJAX search endpoint
header('Content-Type: text/html; charset=utf-8');

require_once 'config/database.php';
require_once 'includes/functions.php';

$query = $_GET['q'] ?? '';

if (empty($query)) {
    echo '<div class="alert alert-info">Masukkan kata kunci untuk mencari...</div>';
    exit;
}

// Vulnerable search - no input sanitization
try {
    global $pdo;

    // Extremely vulnerable SQL query - direct concatenation
    $sql = "SELECT p.*, u.username, c.name as category_name 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            JOIN categories c ON p.category_id = c.id 
            WHERE (p.title LIKE '%$query%' OR p.content LIKE '%$query%') 
            AND p.status = 'published'
            ORDER BY p.created_at DESC 
            LIMIT 10";

    $stmt = $pdo->query($sql);
    $results = $stmt->fetchAll();

    if (empty($results)) {
        // Vulnerable output - XSS possible
        echo "<div class='alert alert-warning'>Tidak ada hasil untuk pencarian: <strong>$query</strong></div>";
    } else {
        echo "<div class='search-results'>";
        echo "<h5>Hasil pencarian untuk: <strong>$query</strong></h5>";

        foreach ($results as $post) {
            // Vulnerable content display
            $highlightedTitle = str_ireplace($query, '<mark>' . $query . '</mark>', $post['title']);
            $content = substr(strip_tags($post['content']), 0, 150) . '...';
            $highlightedContent = str_ireplace($query, '<mark>' . $query . '</mark>', $content);

            echo "<div class='card mb-2'>";
            echo "<div class='card-body'>";
            echo "<h6 class='card-title'>";
            echo "<a href='post.php?id={$post['id']}' class='text-decoration-none'>";
            echo $highlightedTitle; // Vulnerable to XSS
            echo "</a>";
            echo "</h6>";
            echo "<p class='card-text'>";
            echo $highlightedContent; // Vulnerable to XSS
            echo "</p>";
            echo "<small class='text-muted'>";
            echo "oleh " . htmlspecialchars($post['username']);
            echo " di " . htmlspecialchars($post['category_name']);
            echo " • " . timeAgo($post['created_at']);
            echo "</small>";
            echo "</div>";
            echo "</div>";
        }

        echo "</div>";

        // Add vulnerable JavaScript for additional functionality
        echo "<script>";
        echo "document.querySelectorAll('.search-results a').forEach(function(link) {";
        echo "    link.addEventListener('click', function(e) {";
        echo "        // Vulnerable: Direct query parameter injection";
        echo "        const url = this.href + '?ref=' + encodeURIComponent('" . $query . "');";
        echo "        this.href = url;";
        echo "    });";
        echo "});";
        echo "</script>";
    }
} catch (PDOException $e) {
    // Vulnerable error display - shows SQL details
    echo "<div class='alert alert-danger'>";
    echo "<strong>Database Error:</strong><br>";
    echo "Query: $sql<br>";
    echo "Error: " . $e->getMessage();
    echo "</div>";
}

// Add tracking pixel (vulnerable to various attacks)
echo "<img src='track.php?q=" . urlencode($query) . "&ip=" . $_SERVER['REMOTE_ADDR'] . "' width='1' height='1' style='display:none;'>";

// Vulnerable session handling
if (isset($_SESSION['user_id'])) {
    // Update search history without sanitization
    $searchHistory = $_SESSION['search_history'] ?? [];
    $searchHistory[] = [
        'query' => $query,
        'timestamp' => time(),
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
    ];

    // Keep only last 10 searches
    if (count($searchHistory) > 10) {
        array_shift($searchHistory);
    }

    $_SESSION['search_history'] = $searchHistory;
}
