<?php

/**
 * Final Integration Test
 * Tests all evasion components working together
 */

// Include required components
require_once 'evasion_engine.php';

// Error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: text/html; charset=UTF-8');
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Final Integration Test - Advanced IDS/IPS Evasion Platform</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: #fff;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.8);
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }

        h1 {
            color: #00ff41;
            text-align: center;
            text-shadow: 0 0 10px #00ff41;
            margin-bottom: 30px;
        }

        .test-section {
            background: rgba(0, 30, 60, 0.6);
            border: 1px solid #00ff41;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .test-header {
            color: #00ff41;
            border-bottom: 1px solid #00ff41;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }

        .success {
            color: #00ff41;
        }

        .error {
            color: #ff4444;
        }

        .warning {
            color: #ffaa00;
        }

        .info {
            color: #44aaff;
        }

        pre {
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid #333;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
        }

        .navigation {
            text-align: center;
            margin: 20px 0;
        }

        .nav-link {
            display: inline-block;
            background: linear-gradient(45deg, #00ff41, #00aa30);
            color: #000;
            text-decoration: none;
            padding: 12px 25px;
            border-radius: 25px;
            margin: 5px 10px;
            font-weight: bold;
            transition: all 0.3s ease;
            text-transform: uppercase;
        }

        .nav-link:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 15px rgba(0, 255, 65, 0.4);
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>🛡️ Final Integration Test</h1>
        <p class="info" style="text-align: center;">Comprehensive verification of all evasion platform components</p>

        <div class="navigation">
            <a href="test_evasion_advanced.php" class="nav-link">Advanced Testing</a>
            <a href="payload_generator.php" class="nav-link">Payload Generator</a>
            <a href="master_evasion_demo.php" class="nav-link">Master Demo</a>
            <a href="websocket_evasion.php" class="nav-link">WebSocket Evasion</a>
        </div>

        <?php
        $tests_passed = 0;
        $total_tests = 0;
        $issues_found = [];

        // Test 1: Evasion Engine Class
        echo "<div class='test-section'>";
        echo "<h3 class='test-header'>🔧 Testing Evasion Engine Class</h3>";
        $total_tests++;

        if (class_exists('AdvancedEvasionEngine')) {
            echo "<p class='success'>✅ AdvancedEvasionEngine class loaded successfully</p>";
            $tests_passed++;

            // Test character obfuscation
            $test_string = "SELECT * FROM users";
            $obfuscated = AdvancedEvasionEngine::characterObfuscation($test_string, 'ascii_codes');
            if (!empty($obfuscated)) {
                echo "<p class='success'>✅ Character obfuscation working</p>";
                echo "<pre class='info'>Original: $test_string\nObfuscated: $obfuscated</pre>";
                $tests_passed++;
            } else {
                echo "<p class='error'>❌ Character obfuscation failed</p>";
                $issues_found[] = "Character obfuscation not working";
            }
            $total_tests++;

            // Test dynamic construction
            $sql_parts = ['SELECT', '*', 'FROM', 'users'];
            $dynamic = AdvancedEvasionEngine::dynamicConstruction($sql_parts, 'variable_assembly');
            if (!empty($dynamic)) {
                echo "<p class='success'>✅ Dynamic construction working</p>";
                echo "<pre class='info'>Dynamic SQL: $dynamic</pre>";
                $tests_passed++;
            } else {
                echo "<p class='error'>❌ Dynamic construction failed</p>";
                $issues_found[] = "Dynamic construction not working";
            }
            $total_tests++;

            // Test protocol manipulation
            $headers = ['Content-Type: application/x-www-form-urlencoded'];
            $manipulated = AdvancedEvasionEngine::protocolManipulation($headers, 'content_type_confusion');
            if (!empty($manipulated)) {
                echo "<p class='success'>✅ Protocol manipulation working</p>";
                echo "<pre class='info'>Manipulated headers: " . implode(', ', $manipulated) . "</pre>";
                $tests_passed++;
            } else {
                echo "<p class='error'>❌ Protocol manipulation failed</p>";
                $issues_found[] = "Protocol manipulation not working";
            }
            $total_tests++;
        } else {
            echo "<p class='error'>❌ AdvancedEvasionEngine class not found</p>";
            $issues_found[] = "AdvancedEvasionEngine class missing";
        }
        echo "</div>";

        // Test 2: File Accessibility
        echo "<div class='test-section'>";
        echo "<h3 class='test-header'>📁 Testing File Accessibility</h3>";

        $critical_files = [
            'test_evasion_advanced.php',
            'payload_generator.php',
            'master_evasion_demo.php',
            'websocket_evasion.php',
            'evasion_tester.py',
            'assets/js/client_evasion.js'
        ];

        foreach ($critical_files as $file) {
            $total_tests++;
            if (file_exists($file)) {
                echo "<p class='success'>✅ $file exists and accessible</p>";
                $tests_passed++;
            } else {
                echo "<p class='error'>❌ $file missing or inaccessible</p>";
                $issues_found[] = "$file missing";
            }
        }
        echo "</div>";

        // Test 3: XSS Evasion Techniques
        echo "<div class='test-section'>";
        echo "<h3 class='test-header'>🎭 Testing XSS Evasion Techniques</h3>";
        $total_tests++;

        $xss_payload = "<script>alert('XSS')</script>";
        $contexts = ['html', 'attribute', 'javascript', 'css'];

        try {
            $context_aware = AdvancedEvasionEngine::contextAwarePayloads($xss_payload, $contexts);
            if (!empty($context_aware)) {
                echo "<p class='success'>✅ Context-aware XSS payloads generated</p>";
                $tests_passed++;

                foreach ($context_aware as $context => $payload) {
                    echo "<pre class='info'>$context: " . htmlspecialchars(substr($payload, 0, 100)) . "...</pre>";
                }
            } else {
                echo "<p class='error'>❌ Context-aware XSS generation failed</p>";
                $issues_found[] = "XSS context-aware generation failed";
            }
        } catch (Exception $e) {
            echo "<p class='error'>❌ XSS testing error: " . htmlspecialchars($e->getMessage()) . "</p>";
            $issues_found[] = "XSS testing exception";
        }
        echo "</div>";

        // Test 4: WAF Bypass Techniques
        echo "<div class='test-section'>";
        echo "<h3 class='test-header'>🛡️ Testing WAF Bypass Techniques</h3>";
        $total_tests++;

        $malicious_payload = "' OR 1=1--";
        $waf_types = ['cloudflare', 'akamai', 'aws_waf'];

        try {
            $waf_bypasses = AdvancedEvasionEngine::wafSpecificBypass($malicious_payload, $waf_types);
            if (!empty($waf_bypasses)) {
                echo "<p class='success'>✅ WAF-specific bypasses generated</p>";
                $tests_passed++;

                foreach ($waf_bypasses as $waf => $bypass) {
                    echo "<pre class='info'>$waf: " . htmlspecialchars(substr($bypass, 0, 80)) . "...</pre>";
                }
            } else {
                echo "<p class='error'>❌ WAF bypass generation failed</p>";
                $issues_found[] = "WAF bypass generation failed";
            }
        } catch (Exception $e) {
            echo "<p class='error'>❌ WAF testing error: " . htmlspecialchars($e->getMessage()) . "</p>";
            $issues_found[] = "WAF testing exception";
        }
        echo "</div>";

        // Test 5: Timing Attack Alternatives
        echo "<div class='test-section'>";
        echo "<h3 class='test-header'>⏱️ Testing Timing Attack Alternatives</h3>";
        $total_tests++;

        try {
            $timing_alternatives = AdvancedEvasionEngine::timingAttackAlternatives();
            if (!empty($timing_alternatives)) {
                echo "<p class='success'>✅ Timing attack alternatives available</p>";
                $tests_passed++;

                foreach ($timing_alternatives as $technique => $payload) {
                    echo "<pre class='info'>$technique: " . htmlspecialchars(substr($payload, 0, 80)) . "...</pre>";
                }
            } else {
                echo "<p class='error'>❌ Timing attack alternatives failed</p>";
                $issues_found[] = "Timing attack alternatives failed";
            }
        } catch (Exception $e) {
            echo "<p class='error'>❌ Timing testing error: " . htmlspecialchars($e->getMessage()) . "</p>";
            $issues_found[] = "Timing testing exception";
        }
        echo "</div>";

        // Test 6: Polyglot Generation
        echo "<div class='test-section'>";
        echo "<h3 class='test-header'>🔀 Testing Polyglot Generation</h3>";
        $total_tests++;

        try {
            $contexts = ['html', 'javascript', 'sql'];
            $polyglots = AdvancedEvasionEngine::polyglotGeneration($contexts);
            if (!empty($polyglots)) {
                echo "<p class='success'>✅ Polyglot payloads generated</p>";
                $tests_passed++;

                foreach ($polyglots as $type => $payload) {
                    echo "<pre class='info'>$type: " . htmlspecialchars(substr($payload, 0, 80)) . "...</pre>";
                }
            } else {
                echo "<p class='error'>❌ Polyglot generation failed</p>";
                $issues_found[] = "Polyglot generation failed";
            }
        } catch (Exception $e) {
            echo "<p class='error'>❌ Polyglot testing error: " . htmlspecialchars($e->getMessage()) . "</p>";
            $issues_found[] = "Polyglot testing exception";
        }
        echo "</div>";

        // Final Results
        echo "<div class='test-section'>";
        echo "<h3 class='test-header'>📊 Integration Test Results</h3>";

        $success_rate = round(($tests_passed / $total_tests) * 100, 2);

        echo "<div style='background: rgba(0,0,0,0.8); padding: 20px; border-radius: 8px; margin: 20px 0;'>";
        echo "<h4 style='color: #00ff41; margin-top: 0;'>Summary</h4>";
        echo "<p><strong>Total Tests:</strong> $total_tests</p>";
        echo "<p><strong>Passed:</strong> <span class='success'>$tests_passed</span></p>";
        echo "<p><strong>Failed:</strong> <span class='error'>" . ($total_tests - $tests_passed) . "</span></p>";
        echo "<p><strong>Success Rate:</strong> <span class='" . ($success_rate >= 80 ? 'success' : 'warning') . "'>$success_rate%</span></p>";

        if (empty($issues_found)) {
            echo "<p class='success'><strong>🎉 All components integrated successfully!</strong></p>";
            echo "<p class='info'>The Advanced IDS/IPS Evasion Platform is fully operational and ready for testing.</p>";
        } else {
            echo "<h4 style='color: #ff4444;'>Issues Found:</h4>";
            foreach ($issues_found as $issue) {
                echo "<p class='error'>• $issue</p>";
            }
        }
        echo "</div>";

        // Performance metrics
        echo "<div style='background: rgba(0,30,60,0.8); padding: 15px; border-radius: 8px; margin: 20px 0;'>";
        echo "<h4 style='color: #44aaff; margin-top: 0;'>Platform Capabilities</h4>";
        echo "<p>• <strong>Character-level Obfuscation:</strong> ASCII codes, hex encoding, base64, multi-layer</p>";
        echo "<p>• <strong>Dynamic Construction:</strong> Variable assembly, function decoding, runtime keywords</p>";
        echo "<p>• <strong>Protocol Manipulation:</strong> HTTP pollution, content-type confusion, transfer encoding</p>";
        echo "<p>• <strong>Context-aware XSS:</strong> HTML, attribute, JavaScript, CSS contexts</p>";
        echo "<p>• <strong>WAF Bypasses:</strong> Cloudflare, Akamai, AWS WAF, generic patterns</p>";
        echo "<p>• <strong>Timing Alternatives:</strong> BENCHMARK, mathematical operations, resource exhaustion</p>";
        echo "<p>• <strong>Automation:</strong> Python scripts, batch testing, effectiveness measurement</p>";
        echo "</div>";

        echo "</div>";
        ?>

        <div class="navigation">
            <a href="index.php" class="nav-link">🏠 Home</a>
            <a href="README.md" class="nav-link">📖 Documentation</a>
            <a href="EVASION_DOCUMENTATION.md" class="nav-link">📚 Techniques</a>
        </div>
    </div>

    <script>
        // Add some dynamic effects
        document.addEventListener('DOMContentLoaded', function() {
            // Animate success messages
            const successElements = document.querySelectorAll('.success');
            successElements.forEach((el, index) => {
                setTimeout(() => {
                    el.style.opacity = '0';
                    el.style.transform = 'translateX(-10px)';
                    el.style.transition = 'all 0.3s ease';
                    setTimeout(() => {
                        el.style.opacity = '1';
                        el.style.transform = 'translateX(0)';
                    }, 100);
                }, index * 100);
            });
        });
    </script>
</body>

</html>