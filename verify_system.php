<?php

/**
 * System Verification Script
 * Checks if all forum components are working properly
 */

echo "🔍 Forum System Verification\n";
echo "============================\n\n";

$checks = [];
$baseDir = __DIR__;

// 1. Check database connection
try {
    require_once $baseDir . '/config/database.php';
    $checks['database'] = "✅ Database connection successful";
} catch (Exception $e) {
    $checks['database'] = "❌ Database connection failed: " . $e->getMessage();
}

// 2. Check admin user exists
try {
    $stmt = $pdo->prepare("SELECT username, role FROM users WHERE username = 'admin'");
    $stmt->execute();
    $admin = $stmt->fetch();
    if ($admin) {
        $checks['admin_user'] = "✅ Admin user exists (role: {$admin['role']})";
    } else {
        $checks['admin_user'] = "❌ Admin user not found";
    }
} catch (Exception $e) {
    $checks['admin_user'] = "❌ Could not verify admin user: " . $e->getMessage();
}

// 3. Check required files
$requiredFiles = [
    'index.php' => 'Main forum page',
    'login.php' => 'Login page',
    'admin/index.php' => 'Admin dashboard',
    'includes/functions.php' => 'Core functions',
    'test-payloads.html' => 'Testing interface',
    'evasion_tester.py' => 'Python testing script'
];

foreach ($requiredFiles as $file => $description) {
    if (file_exists($baseDir . '/' . $file)) {
        $checks["file_$file"] = "✅ $description found";
    } else {
        $checks["file_$file"] = "❌ $description missing";
    }
}

// 4. Check vulnerable functions
try {
    require_once $baseDir . '/includes/functions.php';
    if (function_exists('getUserByUsername')) {
        $checks['functions'] = "✅ Core functions loaded";
    } else {
        $checks['functions'] = "❌ Core functions not loaded properly";
    }
} catch (Exception $e) {
    $checks['functions'] = "❌ Functions error: " . $e->getMessage();
}

// 5. Check sample data
try {
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM posts");
    $postCount = $stmt->fetch()['count'];
    $checks['sample_data'] = "✅ Sample data exists ($postCount posts)";
} catch (Exception $e) {
    $checks['sample_data'] = "❌ Sample data check failed: " . $e->getMessage();
}

// Print results
foreach ($checks as $check => $result) {
    echo "$result\n";
}

// Final status
$failures = array_filter($checks, function ($check) {
    return strpos($check, '❌') === 0;
});

echo "\n" . str_repeat("=", 40) . "\n";
if (empty($failures)) {
    echo "🎉 ALL SYSTEMS OPERATIONAL!\n";
    echo "Forum is ready for vulnerability testing.\n\n";
    echo "Quick Start:\n";
    echo "1. Visit: http://localhost/Musywar\n";
    echo "2. Login: admin / password\n";
    echo "3. Start testing with TESTING_GUIDE.md\n";
} else {
    echo "⚠️  SOME ISSUES DETECTED:\n";
    foreach ($failures as $failure) {
        echo "   $failure\n";
    }
    echo "\nPlease fix these issues before testing.\n";
}

echo "\n🔐 Security Warning: This system contains intentional vulnerabilities!\n";
echo "Use only for authorized testing and educational purposes.\n";
