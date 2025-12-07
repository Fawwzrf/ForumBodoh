<?php

/**
 * Simple Setup Script for Vulnerable Forum
 */

echo "=== Forum Masyarakat Simple Setup ===\n";
echo "Setting up vulnerable forum system...\n";

try {
    // Database configuration
    $host = 'localhost';
    $username = 'root';
    $password = '';

    // Connect to MySQL server
    $pdo = new PDO("mysql:host=$host", $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
    echo "1. Connected to MySQL server ✓\n";

    // Read and execute the simplified schema
    $schema = file_get_contents(__DIR__ . '/database/schema_simple.sql');
    $statements = explode(';', $schema);

    foreach ($statements as $statement) {
        $statement = trim($statement);
        if (!empty($statement)) {
            try {
                $pdo->exec($statement);
            } catch (PDOException $e) {
                // Only show errors that aren't about duplicates
                if (strpos($e->getMessage(), 'Duplicate entry') === false) {
                    echo "Warning: " . $e->getMessage() . "\n";
                }
            }
        }
    }

    echo "2. Database schema imported ✓\n";

    // Test database connection with forum database
    $pdo = new PDO("mysql:host=$host;dbname=forum_masyarakat", $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);

    // Verify admin user exists
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = 'admin'");
    $stmt->execute();
    $admin = $stmt->fetch();

    if ($admin) {
        echo "3. Admin user verified ✓\n";
        echo "\n=== Setup Complete ===\n";
        echo "Forum is ready for vulnerability testing!\n\n";
        echo "Access the forum at: http://localhost/Musywar\n";
        echo "Admin login: admin / password\n";
        echo "Moderator login: moderator / password\n\n";
        echo "⚠️  SECURITY WARNING: This forum contains intentional vulnerabilities!\n";
        echo "Use only for authorized security testing and education.\n\n";
        echo "Available vulnerabilities:\n";
        echo "- XSS in posts, replies, search\n";
        echo "- SQL injection in login and search\n";
        echo "- CSRF on all forms\n";
        echo "- Information disclosure\n";
        echo "\nRun: python evasion_tester.py for testing tools\n";
    } else {
        echo "Error: Could not verify admin user\n";
    }
} catch (Exception $e) {
    echo "Setup Error: " . $e->getMessage() . "\n";
    echo "Please check your MySQL configuration and try again.\n";
}
