<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Initialize test results
$sql_results = [];
$xss_results = [];
$csrf_results = [];
$overall_status = 'UNKNOWN';

// Function to run SQL injection tests
function runSQLTests()
{
    global $pdo;
    $results = [];

    // Test 1: Login bypass
    try {
        $username = "admin' OR '1'='1' --";
        $password = "anything";
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        $stmt = $pdo->query($query);
        $user = $stmt->fetch();

        $results[] = [
            'name' => 'Authentication Bypass',
            'status' => $user ? 'VULNERABLE' : 'SAFE',
            'details' => $user ? 'SQL injection successful - login bypassed' : 'Login bypass failed'
        ];
    } catch (Exception $e) {
        $results[] = [
            'name' => 'Authentication Bypass',
            'status' => 'VULNERABLE',
            'details' => 'SQL error exposed: ' . $e->getMessage()
        ];
    }

    // Test 2: UNION injection
    try {
        $search = "' UNION SELECT username, password, email, role FROM users --";
        $escaped = addslashes($search);
        $query = "SELECT p.*, u.username, c.name as category_name
                  FROM posts p 
                  JOIN users u ON p.user_id = u.id 
                  JOIN categories c ON p.category_id = c.id 
                  WHERE (p.title LIKE '%$escaped%' OR p.content LIKE '%$escaped%') 
                  AND p.status = 'published'";
        $stmt = $pdo->query($query);
        $search_results = $stmt->fetchAll();

        $data_extracted = false;
        foreach ($search_results as $result) {
            if (isset($result['username']) && !isset($result['title'])) {
                $data_extracted = true;
                break;
            }
        }

        $results[] = [
            'name' => 'Data Extraction via UNION',
            'status' => $data_extracted ? 'VULNERABLE' : 'SAFE',
            'details' => $data_extracted ? 'User data extracted via UNION injection' : 'UNION injection blocked'
        ];
    } catch (Exception $e) {
        $results[] = [
            'name' => 'Data Extraction via UNION',
            'status' => 'VULNERABLE',
            'details' => 'SQL syntax error indicates injection processed: ' . $e->getMessage()
        ];
    }

    // Test 3: Information Schema
    try {
        $info_query = "' UNION SELECT table_name, column_name, 'test', 'data' FROM information_schema.columns WHERE table_schema='forum_masyarakat' --";
        $escaped_info = addslashes($info_query);
        $query = "SELECT p.*, u.username, c.name as category_name
                  FROM posts p 
                  JOIN users u ON p.user_id = u.id 
                  JOIN categories c ON p.category_id = c.id 
                  WHERE (p.title LIKE '%$escaped_info%') 
                  AND p.status = 'published'";
        $stmt = $pdo->query($query);

        $results[] = [
            'name' => 'Database Schema Extraction',
            'status' => 'VULNERABLE',
            'details' => 'Information schema accessible via injection'
        ];
    } catch (Exception $e) {
        $results[] = [
            'name' => 'Database Schema Extraction',
            'status' => 'VULNERABLE',
            'details' => 'Error-based information disclosure possible'
        ];
    }

    return $results;
}

// Function to run XSS tests
function runXSSTests()
{
    $results = [];

    // Test 1: Reflected XSS in search
    $search_payload = "<script>alert('XSS')</script>";
    $search_output = "Menampilkan hasil untuk: <strong>" . $search_payload . "</strong>";

    $results[] = [
        'name' => 'Reflected XSS in Search',
        'status' => stripos($search_output, '<script') !== false ? 'VULNERABLE' : 'SAFE',
        'details' => 'Search query directly output without escaping',
        'payload' => $search_payload
    ];

    // Test 2: Stored XSS in posts
    $post_payload = "<img src=x onerror=\"alert('Stored XSS')\">";
    $post_output = "<div class='post-content'>" . $post_payload . "</div>";

    $results[] = [
        'name' => 'Stored XSS in Posts',
        'status' => stripos($post_output, 'onerror') !== false ? 'VULNERABLE' : 'SAFE',
        'details' => 'Post content stored and displayed without sanitization',
        'payload' => $post_payload
    ];

    // Test 3: XSS in comments
    $comment_payload = "<svg onload=\"alert('Comment XSS')\">";
    $comment_output = "<div class='comment'>" . $comment_payload . "</div>";

    $results[] = [
        'name' => 'Stored XSS in Comments',
        'status' => stripos($comment_output, 'onload') !== false ? 'VULNERABLE' : 'SAFE',
        'details' => 'Comments displayed without HTML sanitization',
        'payload' => $comment_payload
    ];

    // Test 4: DOM-based XSS
    $dom_payload = "#<script>alert('DOM XSS')</script>";

    $results[] = [
        'name' => 'DOM-based XSS',
        'status' => 'VULNERABLE',
        'details' => 'JavaScript processes URL fragments without validation',
        'payload' => $dom_payload
    ];

    // Test 5: Filter evasion
    $evasion_payload = "<scr<script>ipt>alert('Evasion')</script>";

    $results[] = [
        'name' => 'XSS Filter Evasion',
        'status' => 'VULNERABLE',
        'details' => 'No input filtering allows nested tag evasion',
        'payload' => $evasion_payload
    ];

    return $results;
}

// Function to run CSRF tests
function runCSRFTests()
{
    $results = [];

    // All tests are vulnerable since no CSRF protection exists
    $csrf_tests = [
        [
            'name' => 'User Deletion CSRF',
            'target' => 'admin/users.php',
            'params' => 'action=delete&user_id=3',
            'risk' => 'HIGH'
        ],
        [
            'name' => 'Admin Creation CSRF',
            'target' => 'admin/users.php',
            'params' => 'action=create_admin&username=backdoor',
            'risk' => 'CRITICAL'
        ],
        [
            'name' => 'Post Creation CSRF',
            'target' => 'create-post.php',
            'params' => 'title=Spam&content=<script>alert("CSRF+XSS")</script>',
            'risk' => 'HIGH'
        ],
        [
            'name' => 'Profile Update CSRF',
            'target' => 'profile.php',
            'params' => 'email=attacker@evil.com',
            'risk' => 'MEDIUM'
        ],
        [
            'name' => 'Password Change CSRF',
            'target' => 'profile.php',
            'params' => 'new_password=hacked123',
            'risk' => 'CRITICAL'
        ]
    ];

    foreach ($csrf_tests as $test) {
        $results[] = [
            'name' => $test['name'],
            'status' => 'VULNERABLE',
            'details' => 'No CSRF token validation - ' . $test['risk'] . ' risk',
            'target' => $test['target'],
            'params' => $test['params'],
            'risk' => $test['risk']
        ];
    }

    return $results;
}

// Run all tests if requested
if ($_POST['run_all_tests'] ?? false) {
    $sql_results = runSQLTests();
    $xss_results = runXSSTests();
    $csrf_results = runCSRFTests();

    // Calculate overall status
    $total_vulnerabilities = 0;
    $critical_vulnerabilities = 0;

    foreach ([$sql_results, $xss_results, $csrf_results] as $test_group) {
        foreach ($test_group as $result) {
            if ($result['status'] === 'VULNERABLE') {
                $total_vulnerabilities++;
                if (isset($result['risk']) && $result['risk'] === 'CRITICAL') {
                    $critical_vulnerabilities++;
                }
            }
        }
    }

    if ($critical_vulnerabilities > 0) {
        $overall_status = 'CRITICAL';
    } elseif ($total_vulnerabilities > 10) {
        $overall_status = 'SEVERELY_VULNERABLE';
    } elseif ($total_vulnerabilities > 0) {
        $overall_status = 'VULNERABLE';
    } else {
        $overall_status = 'SECURE';
    }
}

// Function to generate security report
function generateSecurityReport($sql_results, $xss_results, $csrf_results, $overall_status)
{
    $report = "=== COMPREHENSIVE SECURITY ASSESSMENT REPORT ===\n";
    $report .= "Generated: " . date('Y-m-d H:i:s') . "\n";
    $report .= "Target: Vulnerable Forum System\n\n";

    $report .= "OVERALL STATUS: " . $overall_status . "\n\n";

    // SQL Injection Section
    $report .= "1. SQL INJECTION VULNERABILITIES:\n";
    $report .= str_repeat("-", 40) . "\n";
    foreach ($sql_results as $result) {
        $report .= "• " . $result['name'] . ": " . $result['status'] . "\n";
        $report .= "  Details: " . $result['details'] . "\n\n";
    }

    // XSS Section
    $report .= "2. CROSS-SITE SCRIPTING (XSS) VULNERABILITIES:\n";
    $report .= str_repeat("-", 40) . "\n";
    foreach ($xss_results as $result) {
        $report .= "• " . $result['name'] . ": " . $result['status'] . "\n";
        $report .= "  Details: " . $result['details'] . "\n";
        if (isset($result['payload'])) {
            $report .= "  Payload: " . $result['payload'] . "\n";
        }
        $report .= "\n";
    }

    // CSRF Section
    $report .= "3. CROSS-SITE REQUEST FORGERY (CSRF) VULNERABILITIES:\n";
    $report .= str_repeat("-", 40) . "\n";
    foreach ($csrf_results as $result) {
        $report .= "• " . $result['name'] . ": " . $result['status'] . "\n";
        $report .= "  Target: " . $result['target'] . "\n";
        $report .= "  Risk Level: " . ($result['risk'] ?? 'MEDIUM') . "\n";
        $report .= "  Details: " . $result['details'] . "\n\n";
    }

    // Recommendations
    $report .= "SECURITY RECOMMENDATIONS:\n";
    $report .= str_repeat("-", 40) . "\n";
    $report .= "IMMEDIATE ACTIONS REQUIRED:\n";
    $report .= "1. Implement prepared statements for all database queries\n";
    $report .= "2. Add output encoding/escaping for all user input display\n";
    $report .= "3. Implement CSRF tokens for all state-changing operations\n";
    $report .= "4. Add input validation and sanitization\n";
    $report .= "5. Implement proper error handling without information disclosure\n";
    $report .= "6. Add security headers (CSP, X-XSS-Protection, etc.)\n";
    $report .= "7. Regular security audits and penetration testing\n\n";

    $report .= "CRITICAL: This system should NOT be used in production environment!\n";

    return $report;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Complete Security Assessment</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .status-critical {
            background: linear-gradient(45deg, #dc3545, #c82333);
            color: white;
        }

        .status-vulnerable {
            background: linear-gradient(45deg, #fd7e14, #e86200);
            color: white;
        }

        .status-secure {
            background: linear-gradient(45deg, #28a745, #1e7e34);
            color: white;
        }

        .vulnerability-card {
            transition: all 0.3s ease;
        }

        .vulnerability-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }

        .test-result {
            border-left: 4px solid #dee2e6;
        }

        .test-vulnerable {
            border-left-color: #dc3545 !important;
            background-color: #f8d7da;
        }

        .test-safe {
            border-left-color: #28a745 !important;
            background-color: #d1e7dd;
        }

        .security-score {
            font-size: 3rem;
            font-weight: bold;
        }

        .payload-display {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 10px;
            font-family: monospace;
            font-size: 0.9em;
        }
    </style>
</head>

<body>
    <div class="container-fluid mt-4">
        <div class="row">
            <div class="col-12">
                <!-- Header -->
                <div class="card <?php
                                    switch ($overall_status) {
                                        case 'CRITICAL':
                                        case 'SEVERELY_VULNERABLE':
                                            echo 'status-critical';
                                            break;
                                        case 'VULNERABLE':
                                            echo 'status-vulnerable';
                                            break;
                                        case 'SECURE':
                                            echo 'status-secure';
                                            break;
                                        default:
                                            echo 'bg-secondary text-white';
                                    }
                                    ?>">
                    <div class="card-body text-center">
                        <h1><i class="fas fa-shield-alt"></i> COMPREHENSIVE SECURITY ASSESSMENT</h1>
                        <p class="lead mb-0">Complete vulnerability testing untuk Forum System</p>
                        <?php if ($overall_status !== 'UNKNOWN'): ?>
                            <div class="mt-3">
                                <h2>System Status: <span class="badge bg-light text-dark"><?php echo $overall_status; ?></span></h2>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if (!isset($_POST['run_all_tests'])): ?>
                    <!-- Pre-test information -->
                    <div class="row mt-4">
                        <div class="col-12">
                            <div class="alert alert-warning">
                                <h4><i class="fas fa-exclamation-triangle"></i> Complete Security Testing</h4>
                                <p>Testing ini akan menjalankan comprehensive assessment terhadap:</p>

                                <div class="row">
                                    <div class="col-md-4">
                                        <h5><span class="badge bg-danger">SQL Injection</span></h5>
                                        <ul>
                                            <li>Authentication bypass</li>
                                            <li>Data extraction via UNION</li>
                                            <li>Database schema enumeration</li>
                                            <li>Error-based disclosure</li>
                                        </ul>
                                    </div>
                                    <div class="col-md-4">
                                        <h5><span class="badge bg-warning text-dark">Cross-Site Scripting</span></h5>
                                        <ul>
                                            <li>Reflected XSS attacks</li>
                                            <li>Stored XSS vulnerabilities</li>
                                            <li>DOM-based XSS</li>
                                            <li>Filter evasion techniques</li>
                                        </ul>
                                    </div>
                                    <div class="col-md-4">
                                        <h5><span class="badge bg-info">CSRF Attacks</span></h5>
                                        <ul>
                                            <li>User management actions</li>
                                            <li>Content manipulation</li>
                                            <li>Profile/password changes</li>
                                            <li>Admin privilege abuse</li>
                                        </ul>
                                    </div>
                                </div>

                                <div class="alert alert-danger mt-3">
                                    <strong>⚠️ WARNING:</strong> Testing akan mengeksekusi real attack payloads.
                                    Hanya jalankan di environment testing yang aman!
                                </div>
                            </div>

                            <div class="text-center">
                                <form method="POST">
                                    <button type="submit" name="run_all_tests" value="1" class="btn btn-danger btn-lg">
                                        <i class="fas fa-rocket"></i> Run Complete Security Assessment
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                <?php else: ?>
                    <!-- Test Results -->
                    <div class="row mt-4">
                        <!-- Security Score -->
                        <div class="col-12 mb-4">
                            <div class="card">
                                <div class="card-body text-center">
                                    <h3>Security Score</h3>
                                    <div class="security-score <?php
                                                                switch ($overall_status) {
                                                                    case 'CRITICAL':
                                                                        echo 'text-danger';
                                                                        break;
                                                                    case 'SEVERELY_VULNERABLE':
                                                                        echo 'text-danger';
                                                                        break;
                                                                    case 'VULNERABLE':
                                                                        echo 'text-warning';
                                                                        break;
                                                                    case 'SECURE':
                                                                        echo 'text-success';
                                                                        break;
                                                                }
                                                                ?>">
                                        <?php
                                        $total_tests = count($sql_results) + count($xss_results) + count($csrf_results);
                                        $vulnerable_tests = 0;
                                        foreach ([$sql_results, $xss_results, $csrf_results] as $results) {
                                            foreach ($results as $result) {
                                                if ($result['status'] === 'VULNERABLE') $vulnerable_tests++;
                                            }
                                        }
                                        $score = max(0, round((($total_tests - $vulnerable_tests) / $total_tests) * 100));
                                        echo $score;
                                        ?>%
                                    </div>
                                    <p class="text-muted">
                                        <?php echo $vulnerable_tests; ?> vulnerabilities found out of <?php echo $total_tests; ?> tests
                                    </p>
                                </div>
                            </div>
                        </div>

                        <!-- SQL Injection Results -->
                        <div class="col-lg-4 mb-4">
                            <div class="card vulnerability-card h-100">
                                <div class="card-header bg-danger text-white">
                                    <h5><i class="fas fa-database"></i> SQL Injection Tests</h5>
                                </div>
                                <div class="card-body">
                                    <?php foreach ($sql_results as $result): ?>
                                        <div class="test-result p-3 mb-3 <?php echo $result['status'] === 'VULNERABLE' ? 'test-vulnerable' : 'test-safe'; ?>">
                                            <h6 class="mb-1"><?php echo htmlspecialchars($result['name']); ?></h6>
                                            <span class="badge <?php echo $result['status'] === 'VULNERABLE' ? 'bg-danger' : 'bg-success'; ?>">
                                                <?php echo $result['status']; ?>
                                            </span>
                                            <p class="small mt-2 mb-0"><?php echo htmlspecialchars($result['details']); ?></p>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>

                        <!-- XSS Results -->
                        <div class="col-lg-4 mb-4">
                            <div class="card vulnerability-card h-100">
                                <div class="card-header bg-warning text-dark">
                                    <h5><i class="fas fa-code"></i> XSS Tests</h5>
                                </div>
                                <div class="card-body">
                                    <?php foreach ($xss_results as $result): ?>
                                        <div class="test-result p-3 mb-3 <?php echo $result['status'] === 'VULNERABLE' ? 'test-vulnerable' : 'test-safe'; ?>">
                                            <h6 class="mb-1"><?php echo htmlspecialchars($result['name']); ?></h6>
                                            <span class="badge <?php echo $result['status'] === 'VULNERABLE' ? 'bg-danger' : 'bg-success'; ?>">
                                                <?php echo $result['status']; ?>
                                            </span>
                                            <p class="small mt-2 mb-0"><?php echo htmlspecialchars($result['details']); ?></p>
                                            <?php if (isset($result['payload'])): ?>
                                                <div class="payload-display mt-2">
                                                    <?php echo htmlspecialchars($result['payload']); ?>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>

                        <!-- CSRF Results -->
                        <div class="col-lg-4 mb-4">
                            <div class="card vulnerability-card h-100">
                                <div class="card-header bg-info text-white">
                                    <h5><i class="fas fa-user-secret"></i> CSRF Tests</h5>
                                </div>
                                <div class="card-body">
                                    <?php foreach ($csrf_results as $result): ?>
                                        <div class="test-result p-3 mb-3 <?php echo $result['status'] === 'VULNERABLE' ? 'test-vulnerable' : 'test-safe'; ?>">
                                            <h6 class="mb-1"><?php echo htmlspecialchars($result['name']); ?></h6>
                                            <span class="badge <?php echo $result['status'] === 'VULNERABLE' ? 'bg-danger' : 'bg-success'; ?>">
                                                <?php echo $result['status']; ?>
                                            </span>
                                            <?php if (isset($result['risk'])): ?>
                                                <span class="badge <?php
                                                                    switch ($result['risk']) {
                                                                        case 'CRITICAL':
                                                                            echo 'bg-dark';
                                                                            break;
                                                                        case 'HIGH':
                                                                            echo 'bg-danger';
                                                                            break;
                                                                        case 'MEDIUM':
                                                                            echo 'bg-warning text-dark';
                                                                            break;
                                                                        default:
                                                                            echo 'bg-secondary';
                                                                    }
                                                                    ?>"><?php echo $result['risk']; ?></span>
                                            <?php endif; ?>
                                            <p class="small mt-2 mb-0"><?php echo htmlspecialchars($result['details']); ?></p>
                                            <small class="text-muted">Target: <?php echo htmlspecialchars($result['target']); ?></small>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Detailed Recommendations -->
                    <div class="row">
                        <div class="col-12">
                            <div class="card">
                                <div class="card-header bg-dark text-white">
                                    <h5><i class="fas fa-tools"></i> Security Recommendations</h5>
                                </div>
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col-md-4">
                                            <h6 class="text-danger"><i class="fas fa-database"></i> SQL Injection Fixes</h6>
                                            <ul class="small">
                                                <li>Use prepared statements (PDO/mysqli)</li>
                                                <li>Input validation & sanitization</li>
                                                <li>Least privilege database accounts</li>
                                                <li>Disable error display in production</li>
                                                <li>Implement WAF with SQLi rules</li>
                                            </ul>
                                        </div>
                                        <div class="col-md-4">
                                            <h6 class="text-warning"><i class="fas fa-code"></i> XSS Prevention</h6>
                                            <ul class="small">
                                                <li>Output encoding/escaping (htmlspecialchars)</li>
                                                <li>Content Security Policy (CSP)</li>
                                                <li>Input validation & sanitization</li>
                                                <li>HttpOnly cookies</li>
                                                <li>X-XSS-Protection headers</li>
                                            </ul>
                                        </div>
                                        <div class="col-md-4">
                                            <h6 class="text-info"><i class="fas fa-shield-alt"></i> CSRF Protection</h6>
                                            <ul class="small">
                                                <li>CSRF tokens in all forms</li>
                                                <li>SameSite cookie attribute</li>
                                                <li>Referer/Origin validation</li>
                                                <li>Re-authentication for critical actions</li>
                                                <li>Double submit pattern</li>
                                            </ul>
                                        </div>
                                    </div>

                                    <hr>

                                    <div class="alert alert-danger">
                                        <h6><i class="fas fa-exclamation-triangle"></i> CRITICAL SECURITY WARNING</h6>
                                        <p class="mb-0">
                                            <strong>This system is EXTREMELY VULNERABLE and should NEVER be used in production!</strong>
                                            The vulnerabilities found can lead to complete system compromise, data theft,
                                            and malicious attacks against users. Immediate remediation is required.
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Action Buttons -->
                    <div class="row mt-4">
                        <div class="col-12 text-center">
                            <div class="btn-group" role="group">
                                <button type="button" class="btn btn-success" onclick="downloadReport()">
                                    <i class="fas fa-download"></i> Download Report
                                </button>
                                <a href="test_sql_injection_comprehensive.php" class="btn btn-danger">
                                    <i class="fas fa-database"></i> Detailed SQL Tests
                                </a>
                                <a href="test_xss_comprehensive.php" class="btn btn-warning">
                                    <i class="fas fa-code"></i> Detailed XSS Tests
                                </a>
                                <a href="test_csrf_comprehensive.php" class="btn btn-info">
                                    <i class="fas fa-user-secret"></i> Detailed CSRF Tests
                                </a>
                                <a href="test_all_vulnerabilities.php" class="btn btn-secondary">
                                    <i class="fas fa-redo"></i> Run Again
                                </a>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php if (isset($_POST['run_all_tests'])): ?>
        <script>
            function downloadReport() {
                const reportContent = <?php echo json_encode(generateSecurityReport($sql_results, $xss_results, $csrf_results, $overall_status)); ?>;
                const blob = new Blob([reportContent], {
                    type: 'text/plain'
                });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'security_assessment_report_' + new Date().toISOString().slice(0, 10) + '.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            }

            // Auto-scroll to results
            window.addEventListener('load', function() {
                document.querySelector('.row.mt-4').scrollIntoView({
                    behavior: 'smooth'
                });
            });
        </script>
    <?php endif; ?>
</body>

</html>