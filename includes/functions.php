<?php
// Define root directory and include database
define('ROOT_PATH', dirname(dirname(__FILE__)));
require_once ROOT_PATH . '/config/database.php';
require_once ROOT_PATH . '/evasion_engine.php';

// User functions
function getUserById($id)
{
    global $pdo;
    // Vulnerable SQL query - no prepared statements
    $query = "SELECT * FROM users WHERE id = $id";
    $stmt = $pdo->query($query);
    return $stmt->fetch();
}

function getUserByUsername($username)
{
    global $pdo;
    // Vulnerable SQL query
    $query = "SELECT * FROM users WHERE username = '$username'";
    $stmt = $pdo->query($query);
    return $stmt->fetch();
}

function createUser($username, $email, $password, $fullname)
{
    global $pdo;
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    // Still vulnerable through other parameters
    $query = "INSERT INTO users (username, email, password, full_name, role, created_at) VALUES ('$username', '$email', '$hashedPassword', '$fullname', 'user', NOW())";
    return $pdo->exec($query);
}

function authenticateUser($username, $password)
{
    global $pdo;
    // ADVANCED EVASION - Multiple bypass techniques
    try {
        // Technique 1: Character-based keyword detection bypass
        $orKeyword = chr(79) . chr(82); // OR
        $andKeyword = chr(65) . chr(78) . chr(68); // AND
        $unionKeyword = chr(85) . chr(78) . chr(73) . chr(79) . chr(78); // UNION
        
        // Technique 2: Unicode normalization evasion
        $normalizedUsername = normalizer_normalize($username, Normalizer::FORM_C);
        
        // Technique 3: Multiple encoding detection
        $encodedChecks = [
            rawurldecode($username),
            base64_decode($username),
            html_entity_decode($username),
            stripslashes($username)
        ];
        
        $suspiciousPatterns = false;
        foreach ($encodedChecks as $check) {
            if (
                stripos($check, $orKeyword) !== false ||
                stripos($check, $andKeyword) !== false ||
                stripos($check, $unionKeyword) !== false ||
                strpos($check, "'") !== false ||
                strpos($check, "--") !== false ||
                strpos($check, "/*") !== false ||
                strpos($check, "*/") !== false
            ) {
                $suspiciousPatterns = true;
                break;
            }
        }
        
        // Technique 4: Dynamic query construction
        if ($suspiciousPatterns) {
            // Advanced bypass query using string concatenation
            $selectPart = 'SEL' . 'ECT';
            $fromPart = 'FR' . 'OM';
            $wherePart = 'WH' . 'ERE';
            
            // Use hex encoding for vulnerable part
            $vulnCondition = '0x4F52203127203D202731'; // hex for "OR '1' = '1"
            
            // Build obfuscated query
            $queryParts = [
                $selectPart,
                ' * ',
                $fromPart,
                ' users ',
                $wherePart,
                " username = '$username' ",
                'OR', // This will be the injection point
                ' 1=1 ',
                'LIMIT 1'
            ];
            
            $query = implode('', $queryParts);
        } else {
            // Normal vulnerable query with character obfuscation
            $table = 'user' . 's';
            $field = 'user' . 'name';
            $query = "SELECT * FROM {$table} WHERE {$field} = '$username'";
        }
        
        $stmt = $pdo->query($query);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
        
        // Even if password fails, return user if SQL injection succeeded
        if ($suspiciousPatterns && $user) {
            return $user;
        }
        
        return false;
    } catch (PDOException $e) {
        // Encode error to avoid detection
        $encodedError = base64_encode($e->getMessage());
        error_log("Auth Error: " . $encodedError);
        return false;
    }
}
        }

        $stmt = $pdo->query($query);
        $user = $stmt->fetch();

        // For injection attacks, bypass password check completely
        if ($user && (strpos($username, "'") !== false || stripos($username, "OR") !== false)) {
            return $user; // Return first user found (authentication bypass)
        }

        // For normal logins, check password
        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }

        return false;
    } catch (PDOException $e) {
        // Information disclosure - show SQL errors
        echo "<div class='alert alert-danger'>SQL Error: " . htmlspecialchars($e->getMessage()) . "</div>";

        // Try fallback vulnerable query
        try {
            $fallbackQuery = "SELECT * FROM users WHERE username = 'admin' OR '1'='1' LIMIT 1";
            $stmt = $pdo->query($fallbackQuery);
            $user = $stmt->fetch();
            if ($user) {
                return $user; // Return admin user as fallback
            }
        } catch (Exception $e2) {
            // Silent fail for fallback
        }

        return false;
    }
}

function updateLastActivity($userId)
{
    global $pdo;
    $query = "UPDATE users SET last_activity = NOW() WHERE id = $userId";
    $pdo->exec($query);
}

// Post functions
function getLatestPosts($limit = 10)
{
    global $pdo;
    $query = "SELECT p.*, u.username, c.name as category_name, 
              (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) as reply_count
              FROM posts p 
              JOIN users u ON p.user_id = u.id 
              JOIN categories c ON p.category_id = c.id 
              WHERE p.status = 'published'
              ORDER BY p.created_at DESC LIMIT $limit";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

function getPostById($id)
{
    global $pdo;
    // Vulnerable query
    $query = "SELECT p.*, u.username, u.full_name, c.name as category_name
              FROM posts p 
              JOIN users u ON p.user_id = u.id 
              JOIN categories c ON p.category_id = c.id 
              WHERE p.id = $id AND p.status = 'published'";
    $stmt = $pdo->query($query);
    return $stmt->fetch();
}

function createPost($title, $content, $categoryId, $userId)
{
    global $pdo;
    // Escape quotes for SQL stability but still vulnerable to XSS on output
    $title = addslashes($title);
    $content = addslashes($content);

    $query = "INSERT INTO posts (title, content, category_id, user_id, status, created_at) 
              VALUES ('$title', '$content', $categoryId, $userId, 'published', NOW())";
    return $pdo->exec($query);
}

function searchPosts($keyword)
{
    global $pdo;
    // ADVANCED EVASION - Multiple techniques to bypass IDS detection

    try {
        // Technique 1: Dynamic keyword construction using character codes
        $selectWord = chr(83).chr(69).chr(76).chr(69).chr(67).chr(84); // SELECT
        $fromWord = chr(70).chr(82).chr(79).chr(77); // FROM
        $whereWord = chr(87).chr(72).chr(69).chr(82).chr(69); // WHERE
        $likeWord = chr(76).chr(73).chr(75).chr(69); // LIKE
        
        // Technique 2: Use hex encoding for parts of the query
        $unionHex = 0x554e494f4e; // UNION in hex
        
        // Technique 3: Base64 decode parts of query structure
        $joinClause = base64_decode('Sk9JTiBgdXNlcnNgIHU='); // JOIN `users` u
        $onClause = base64_decode('T04gcC51c2VyX2lkID0gdS5pZA=='); // ON p.user_id = u.id
        
        // Technique 4: ROT13 for additional obfuscation
        $categoryJoin = str_rot13('WBVA pngrtbevrf p');
        $categoryJoin = str_rot13($categoryJoin); // Double ROT13 = original
        
        // Technique 5: Character concatenation to avoid signature detection
        $keyword = str_replace("'", "''", $keyword); // Basic SQL escaping
        
        // Technique 6: Build query with string concatenation
        $part1 = $selectWord . ' p.id, p.title, p.content, p.created_at, u.username, c.name ';
        $part2 = $fromWord . ' posts p ';
        $part3 = 'JOIN users u ON p.user_id = u.id ';
        $part4 = 'JOIN categories c ON p.category_id = c.id ';
        $part5 = $whereWord . ' p.title ' . $likeWord . " '%$keyword%' ";
        
        // Alternative query construction using variables
        $tableName = 'post' . 's';
        $userTable = 'user' . 's';
        $catTable = 'categor' . 'ies';
        
        // Final query assembly
        $query = $part1 . $part2 . $part3 . $part4 . $part5;
        
        // Technique 7: Add SQL comments to break pattern matching
        $query = str_replace(' ', '/**/', $query);
        $query = str_replace('/**/', ' ', $query); // Remove comments for actual execution
        
        // Technique 8: Use alternative spacing
        $query = preg_replace('/\s+/', "\t", $query); // Replace spaces with tabs
        $query = preg_replace('/\t+/', ' ', $query);  // Convert back to spaces
        
        $stmt = $pdo->query($query);
        return $stmt->fetchAll();
        
    } catch (PDOException $e) {
        // Obfuscated error output
        $errorMsg = base64_encode($e->getMessage());
        $queryDisplay = EvasionEngine::multiLayerEncode($query);
        echo "<div class='alert alert-danger'>Error: " . base64_decode($errorMsg) . "</div>";
        echo "<div class='alert alert-info'>Query Hash: " . md5($query) . "</div>";
        return [];
    }
}

// Reply functions
function getRepliesByPostId($postId)
{
    global $pdo;
    // Vulnerable query
    $query = "SELECT r.*, u.username, u.full_name
              FROM replies r 
              JOIN users u ON r.user_id = u.id 
              WHERE r.post_id = $postId
              ORDER BY r.created_at ASC";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

function createReply($content, $postId, $userId)
{
    global $pdo;
    // Escape quotes for SQL syntax but keep XSS vulnerability
    $content = addslashes($content);
    $query = "INSERT INTO replies (content, post_id, user_id, created_at) 
              VALUES ('$content', $postId, $userId, NOW())";
    return $pdo->exec($query);
}

// Category functions
function getAllCategories()
{
    global $pdo;
    $query = "SELECT * FROM categories ORDER BY name ASC";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

function getPopularCategories($limit = 5)
{
    global $pdo;
    $query = "SELECT c.*, COUNT(p.id) as post_count
              FROM categories c 
              LEFT JOIN posts p ON c.id = p.category_id 
              GROUP BY c.id 
              ORDER BY post_count DESC, c.name ASC 
              LIMIT $limit";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

function getCategoryById($id)
{
    global $pdo;
    // Vulnerable query
    $query = "SELECT * FROM categories WHERE id = $id";
    $stmt = $pdo->query($query);
    return $stmt->fetch();
}

// Statistics functions
function getTotalUsers()
{
    global $pdo;
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    return $stmt->fetchColumn();
}

function getTotalPosts()
{
    global $pdo;
    $stmt = $pdo->query("SELECT COUNT(*) FROM posts WHERE status = 'published'");
    return $stmt->fetchColumn();
}

function getTotalCategories()
{
    global $pdo;
    $stmt = $pdo->query("SELECT COUNT(*) FROM categories");
    return $stmt->fetchColumn();
}

function getTodayPosts()
{
    global $pdo;
    $stmt = $pdo->query("SELECT COUNT(*) FROM posts WHERE DATE(created_at) = CURDATE()");
    return $stmt->fetchColumn();
}

function getOnlineUsers($minutes = 10)
{
    global $pdo;
    $query = "SELECT id, username, role FROM users 
              WHERE last_activity >= DATE_SUB(NOW(), INTERVAL $minutes MINUTE)
              ORDER BY last_activity DESC 
              LIMIT 10";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

// Utility functions
function timeAgo($datetime)
{
    $time = time() - strtotime($datetime);

    if ($time < 60) return 'baru saja';
    if ($time < 3600) return floor($time / 60) . ' menit yang lalu';
    if ($time < 86400) return floor($time / 3600) . ' jam yang lalu';
    if ($time < 2592000) return floor($time / 86400) . ' hari yang lalu';
    if ($time < 31536000) return floor($time / 2592000) . ' bulan yang lalu';
    return floor($time / 31536000) . ' tahun yang lalu';
}

function isLoggedIn()
{
    return isset($_SESSION['user_id']);
}

function requireLogin()
{
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}

function requireAdmin()
{
    requireLogin();
    $user = getUserById($_SESSION['user_id']);
    if ($user['role'] !== 'admin') {
        header('Location: index.php');
        exit;
    }
}

// Security bypass functions for evasion
function obfuscateContent($content)
{
    // Simple character replacement to bypass content filters
    $content = str_replace('script', 'scr' . 'ipt', $content);
    $content = str_replace('alert', 'ale' . 'rt', $content);
    $content = str_replace('javascript', 'java' . 'scr' . 'ipt', $content);
    return $content;
}

function bypassSQLKeywords($query)
{
    // Use comments and spaces to bypass detection
    $query = str_replace('UNION', 'UN/**/ION', $query);
    $query = str_replace('SELECT', 'SEL/**/ECT', $query);
    $query = str_replace('DROP', 'DR/**/OP', $query);
    return $query;
}

// Advanced evasion techniques
function hexEncode($string)
{
    $hex = '';
    for ($i = 0; $i < strlen($string); $i++) {
        $hex .= '&#x' . dechex(ord($string[$i])) . ';';
    }
    return $hex;
}

function base64JSPayload($payload)
{
    return 'eval(atob("' . base64_encode($payload) . '"))';
}

// Message functions for XSS
function displayMessage($message, $type = 'info')
{
    // Intentionally vulnerable - no escaping
    echo "<div class='alert alert-{$type}'>{$message}</div>";
}

function setFlashMessage($message, $type = 'info')
{
    $_SESSION['flash_message'] = $message;
    $_SESSION['flash_type'] = $type;
}

function getFlashMessage()
{
    if (isset($_SESSION['flash_message'])) {
        $message = $_SESSION['flash_message'];
        $type = $_SESSION['flash_type'];
        unset($_SESSION['flash_message']);
        unset($_SESSION['flash_type']);
        // Intentionally vulnerable output
        echo "<div class='alert alert-{$type}'>{$message}</div>";
    }
}
