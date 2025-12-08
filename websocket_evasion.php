<?php
/**
 * WebSocket-based Evasion Testing
 * Real-time communication bypass techniques
 */

// Simple WebSocket server simulation for testing
class WebSocketEvasionServer {
    private $clients = [];
    private $evasionTechniques = [];
    
    public function __construct() {
        $this->initializeEvasionTechniques();
    }
    
    private function initializeEvasionTechniques() {
        $this->evasionTechniques = [
            'json_injection' => [
                'name' => 'JSON Message Injection',
                'description' => 'Inject payloads through JSON message structure',
                'payloads' => [
                    '{"type":"search","data":"\\u0027 OR 1=1--"}',
                    '{"type":"update","field":"name","value":"<script>alert(1)</script>"}',
                    '{"cmd":"exec","query":"\\x27 UNION SELECT password FROM users--"}'
                ]
            ],
            
            'protocol_confusion' => [
                'name' => 'Protocol Confusion',
                'description' => 'Mix different protocol formats in WebSocket',
                'payloads' => [
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
                    "GET /admin HTTP/1.1\r\nAuthorization: Bearer fake_token\r\n\r\n",
                    "POST /api/user HTTP/1.1\r\nContent-Length: 100\r\n\r\n{\"admin\":true}"
                ]
            ],
            
            'binary_evasion' => [
                'name' => 'Binary Message Evasion',
                'description' => 'Use binary frames to bypass text-based filters',
                'payloads' => [
                    base64_encode("' OR 1=1--"),
                    bin2hex("<script>alert('binary')</script>"),
                    gzcompress("' UNION SELECT * FROM users--")
                ]
            ],
            
            'fragmented_messages' => [
                'name' => 'Message Fragmentation',
                'description' => 'Split malicious payload across multiple frames',
                'payloads' => [
                    ['frame1' => "'", 'frame2' => ' OR ', 'frame3' => '1=1--'],
                    ['frame1' => '<script>', 'frame2' => 'alert(1)', 'frame3' => '</script>'],
                    ['frame1' => 'UNI', 'frame2' => 'ON SEL', 'frame3' => 'ECT']
                ]
            ],
            
            'ping_pong_evasion' => [
                'name' => 'Ping/Pong Frame Abuse',
                'description' => 'Hide payloads in control frames',
                'payloads' => [
                    'ping:' . base64_encode("' OR 1=1--"),
                    'pong:' . base64_encode('<script>alert(1)</script>'),
                    'close:' . base64_encode('UNION SELECT password FROM users')
                ]
            ]
        ];
    }
    
    public function simulateWebSocketHandshake($headers) {
        // Simulate WebSocket upgrade with potential bypasses
        $response = [
            'status' => 'HTTP/1.1 101 Switching Protocols',
            'upgrade' => 'websocket',
            'connection' => 'Upgrade',
            'sec-websocket-accept' => $this->calculateWebSocketAccept($headers['sec-websocket-key'] ?? ''),
            'sec-websocket-protocol' => $headers['sec-websocket-protocol'] ?? '',
        ];
        
        // Check for protocol smuggling attempts
        $smuggling_detected = $this->detectProtocolSmuggling($headers);
        
        return [
            'response' => $response,
            'smuggling_detected' => $smuggling_detected,
            'connection_established' => !$smuggling_detected
        ];
    }
    
    private function calculateWebSocketAccept($key) {
        $websocket_magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
        return base64_encode(sha1($key . $websocket_magic, true));
    }
    
    private function detectProtocolSmuggling($headers) {
        $suspicious_patterns = [
            'HTTP/1.1' => 'http_injection',
            'Content-Length' => 'content_length_abuse',
            'Transfer-Encoding' => 'transfer_encoding_abuse',
            '\r\n\r\n' => 'header_injection',
            'POST ' => 'method_injection',
            'Authorization:' => 'auth_header_injection'
        ];
        
        foreach ($headers as $name => $value) {
            foreach ($suspicious_patterns as $pattern => $type) {
                if (stripos($value, $pattern) !== false) {
                    return ['type' => $type, 'pattern' => $pattern, 'header' => $name];
                }
            }
        }
        
        return false;
    }
    
    public function processWebSocketMessage($rawMessage, $frameType = 'text') {
        $result = [
            'message_processed' => false,
            'payload_detected' => false,
            'evasion_technique' => null,
            'security_risk' => 'low',
            'decoded_payload' => null,
            'execution_possible' => false
        ];
        
        try {
            switch ($frameType) {
                case 'text':
                    $decoded = $this->processTextFrame($rawMessage);
                    break;
                case 'binary':
                    $decoded = $this->processBinaryFrame($rawMessage);
                    break;
                case 'ping':
                case 'pong':
                    $decoded = $this->processControlFrame($rawMessage, $frameType);
                    break;
                default:
                    $decoded = ['content' => $rawMessage, 'type' => 'unknown'];
            }
            
            $result['decoded_payload'] = $decoded['content'];
            $result['message_processed'] = true;
            
            // Analyze for malicious content
            $analysis = $this->analyzePayloadContent($decoded['content']);
            $result = array_merge($result, $analysis);
            
        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }
        
        return $result;
    }
    
    private function processTextFrame($message) {
        // Try to decode JSON
        $json = json_decode($message, true);
        if ($json !== null) {
            return ['content' => $json, 'type' => 'json'];
        }
        
        // Check for URL encoded content
        $urlDecoded = urldecode($message);
        if ($urlDecoded !== $message) {
            return ['content' => $urlDecoded, 'type' => 'url_encoded'];
        }
        
        // Check for base64 encoded content
        if (base64_encode(base64_decode($message, true)) === $message) {
            $decoded = base64_decode($message);
            return ['content' => $decoded, 'type' => 'base64'];
        }
        
        return ['content' => $message, 'type' => 'plain_text'];
    }
    
    private function processBinaryFrame($binaryData) {
        // Try different binary decodings
        
        // Check if it's base64 encoded text
        if (base64_encode(base64_decode($binaryData, true)) === $binaryData) {
            $decoded = base64_decode($binaryData);
            return ['content' => $decoded, 'type' => 'base64_binary'];
        }
        
        // Check if it's hex encoded
        if (ctype_xdigit($binaryData) && strlen($binaryData) % 2 === 0) {
            $decoded = hex2bin($binaryData);
            return ['content' => $decoded, 'type' => 'hex_binary'];
        }
        
        // Try gzip decompression
        $gzDecoded = @gzuncompress($binaryData);
        if ($gzDecoded !== false) {
            return ['content' => $gzDecoded, 'type' => 'gzip_compressed'];
        }
        
        return ['content' => $binaryData, 'type' => 'raw_binary'];
    }
    
    private function processControlFrame($data, $type) {
        // Control frames shouldn't contain application data, but attackers might abuse them
        $decoded = $data;
        
        // Check for encoded payloads in control frames
        if (base64_encode(base64_decode($data, true)) === $data) {
            $decoded = base64_decode($data);
        }
        
        return ['content' => $decoded, 'type' => $type . '_control'];
    }
    
    private function analyzePayloadContent($content) {
        $analysis = [
            'payload_detected' => false,
            'evasion_technique' => null,
            'security_risk' => 'low',
            'execution_possible' => false,
            'attack_types' => []
        ];
        
        // Convert to string if it's an array/object
        $contentStr = is_string($content) ? $content : json_encode($content);
        
        // SQL Injection patterns
        $sqlPatterns = [
            "/'.*OR.*1.*=.*1/i" => 'sql_or_injection',
            "/UNION.*SELECT/i" => 'sql_union_injection',
            "/EXTRACTVALUE/i" => 'sql_extractvalue',
            "/SLEEP\s*\(/i" => 'sql_time_based',
            "/DROP.*TABLE/i" => 'sql_destructive',
            "/INSERT.*INTO/i" => 'sql_insert_injection',
            "/UPDATE.*SET/i" => 'sql_update_injection',
            "/DELETE.*FROM/i" => 'sql_delete_injection'
        ];
        
        foreach ($sqlPatterns as $pattern => $type) {
            if (preg_match($pattern, $contentStr)) {
                $analysis['payload_detected'] = true;
                $analysis['attack_types'][] = $type;
                $analysis['security_risk'] = 'high';
            }
        }
        
        // XSS patterns
        $xssPatterns = [
            "/<script.*>.*<\/script>/i" => 'xss_script_tag',
            "/javascript\s*:/i" => 'xss_javascript_protocol',
            "/on\w+\s*=\s*[\"'][^\"']*[\"']/i" => 'xss_event_handler',
            "/<iframe.*src.*javascript/i" => 'xss_iframe_injection',
            "/alert\s*\(/i" => 'xss_alert_function',
            "/document\.write/i" => 'xss_document_write',
            "/eval\s*\(/i" => 'xss_eval_injection'
        ];
        
        foreach ($xssPatterns as $pattern => $type) {
            if (preg_match($pattern, $contentStr)) {
                $analysis['payload_detected'] = true;
                $analysis['attack_types'][] = $type;
                $analysis['execution_possible'] = true;
                $analysis['security_risk'] = 'critical';
            }
        }
        
        // Command injection patterns
        $cmdPatterns = [
            "/;\s*(ls|dir|cat|type)\s/i" => 'cmd_file_listing',
            "/\|\s*(nc|netcat)\s/i" => 'cmd_reverse_shell',
            "/&&\s*(rm|del)\s/i" => 'cmd_file_deletion',
            "/`[^`]*`/i" => 'cmd_backtick_execution'
        ];
        
        foreach ($cmdPatterns as $pattern => $type) {
            if (preg_match($pattern, $contentStr)) {
                $analysis['payload_detected'] = true;
                $analysis['attack_types'][] = $type;
                $analysis['security_risk'] = 'critical';
            }
        }
        
        // Determine evasion technique
        if (strpos($contentStr, '\\u') !== false) {
            $analysis['evasion_technique'] = 'unicode_escape';
        } elseif (strpos($contentStr, '\\x') !== false) {
            $analysis['evasion_technique'] = 'hex_escape';
        } elseif (base64_encode(base64_decode($contentStr, true)) === $contentStr) {
            $analysis['evasion_technique'] = 'base64_encoding';
        } elseif (strpos($contentStr, '/*') !== false && strpos($contentStr, '*/') !== false) {
            $analysis['evasion_technique'] = 'comment_injection';
        } elseif (preg_match('/String\.fromCharCode\s*\(/i', $contentStr)) {
            $analysis['evasion_technique'] = 'character_code_obfuscation';
        }
        
        return $analysis;
    }
    
    public function getEvasionTechniques() {
        return $this->evasionTechniques;
    }
    
    public function testWebSocketEvasion() {
        $testResults = [];
        
        foreach ($this->evasionTechniques as $techniqueId => $technique) {
            $testResults[$techniqueId] = [
                'technique' => $technique['name'],
                'description' => $technique['description'],
                'tests' => []
            ];
            
            foreach ($technique['payloads'] as $index => $payload) {
                $testId = $techniqueId . '_' . $index;
                
                if (is_array($payload)) {
                    // Fragmented message test
                    $combinedPayload = implode('', $payload);
                    $result = $this->processWebSocketMessage(json_encode($payload), 'text');
                    $fragmentedResult = $this->testFragmentedMessage($payload);
                    
                    $testResults[$techniqueId]['tests'][$testId] = [
                        'payload' => $payload,
                        'combined_payload' => $combinedPayload,
                        'standard_detection' => $result,
                        'fragmented_detection' => $fragmentedResult
                    ];
                } else {
                    // Standard test
                    $textResult = $this->processWebSocketMessage($payload, 'text');
                    $binaryResult = $this->processWebSocketMessage(base64_encode($payload), 'binary');
                    
                    $testResults[$techniqueId]['tests'][$testId] = [
                        'payload' => $payload,
                        'text_frame_result' => $textResult,
                        'binary_frame_result' => $binaryResult
                    ];
                }
            }
        }
        
        return $testResults;
    }
    
    private function testFragmentedMessage($fragments) {
        $analysis = [
            'individual_detection' => [],
            'combined_detection' => null,
            'evasion_successful' => false
        ];
        
        // Test each fragment individually
        foreach ($fragments as $fragmentId => $fragment) {
            $result = $this->processWebSocketMessage($fragment, 'text');
            $analysis['individual_detection'][$fragmentId] = $result;
        }
        
        // Test combined fragments
        $combined = implode('', $fragments);
        $analysis['combined_detection'] = $this->processWebSocketMessage($combined, 'text');
        
        // Check if fragmentation helped evade detection
        $individualDetected = array_reduce($analysis['individual_detection'], function($carry, $item) {
            return $carry || $item['payload_detected'];
        }, false);
        
        $combinedDetected = $analysis['combined_detection']['payload_detected'];
        
        $analysis['evasion_successful'] = !$individualDetected && $combinedDetected;
        
        return $analysis;
    }
}

// Main testing interface
if ($_GET['action'] ?? false) {
    header('Content-Type: application/json');
    
    $server = new WebSocketEvasionServer();
    
    switch ($_GET['action']) {
        case 'get_techniques':
            echo json_encode($server->getEvasionTechniques());
            break;
            
        case 'test_message':
            $message = $_POST['message'] ?? '';
            $frameType = $_POST['frame_type'] ?? 'text';
            $result = $server->processWebSocketMessage($message, $frameType);
            echo json_encode($result);
            break;
            
        case 'test_handshake':
            $headers = $_POST['headers'] ?? [];
            $result = $server->simulateWebSocketHandshake($headers);
            echo json_encode($result);
            break;
            
        case 'run_full_test':
            $result = $server->testWebSocketEvasion();
            echo json_encode($result, JSON_PRETTY_PRINT);
            break;
            
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSocket Evasion Tester</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .websocket-container { background: #1a1a1a; color: #00ff00; font-family: 'Courier New', monospace; }
        .technique-card { border-left: 4px solid #007bff; margin-bottom: 20px; }
        .payload-display { background: #2d2d2d; padding: 10px; border-radius: 5px; color: #ffff99; }
        .risk-critical { border-left-color: #dc3545 !important; }
        .risk-high { border-left-color: #fd7e14 !important; }
        .risk-medium { border-left-color: #ffc107 !important; }
        .risk-low { border-left-color: #28a745 !important; }
    </style>
</head>
<body>
    <div class="container-fluid mt-4">
        <div class="card websocket-container">
            <div class="card-header">
                <h2><i class="fas fa-plug"></i> 🔌 WebSocket Evasion Tester</h2>
                <p class="mb-0">Advanced WebSocket-based IDS/IPS bypass testing</p>
            </div>
            
            <div class="card-body">
                <div class="row">
                    <!-- Control Panel -->
                    <div class="col-md-4">
                        <h5><i class="fas fa-cog"></i> Control Panel</h5>
                        
                        <div class="mb-3">
                            <label>WebSocket URL:</label>
                            <input type="text" class="form-control" id="wsUrl" value="ws://localhost:8080/ws">
                        </div>
                        
                        <div class="mb-3">
                            <label>Frame Type:</label>
                            <select class="form-select" id="frameType">
                                <option value="text">Text Frame</option>
                                <option value="binary">Binary Frame</option>
                                <option value="ping">Ping Frame</option>
                                <option value="pong">Pong Frame</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label>Custom Message:</label>
                            <textarea class="form-control" id="customMessage" rows="3" 
                                      placeholder='{"type":"search","query":"test"}'></textarea>
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button class="btn btn-primary" onclick="testSingleMessage()">
                                <i class="fas fa-paper-plane"></i> Test Message
                            </button>
                            <button class="btn btn-warning" onclick="runFullEvasionTest()">
                                <i class="fas fa-rocket"></i> Full Evasion Test
                            </button>
                            <button class="btn btn-info" onclick="loadTechniques()">
                                <i class="fas fa-list"></i> Load Techniques
                            </button>
                        </div>
                        
                        <div class="mt-3">
                            <h6>Connection Status:</h6>
                            <div id="connectionStatus" class="badge bg-secondary">Disconnected</div>
                        </div>
                    </div>
                    
                    <!-- Results Panel -->
                    <div class="col-md-8">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5><i class="fas fa-chart-line"></i> Test Results</h5>
                            <button class="btn btn-sm btn-outline-success" onclick="clearResults()">
                                <i class="fas fa-trash"></i> Clear
                            </button>
                        </div>
                        
                        <div id="testResults" style="max-height: 600px; overflow-y: auto;">
                            <div class="text-muted text-center p-4">
                                No tests run yet. Use the control panel to start testing.
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Techniques Display -->
                <div class="row mt-4">
                    <div class="col-12">
                        <h5><i class="fas fa-shield-alt"></i> Available Evasion Techniques</h5>
                        <div id="techniquesDisplay">
                            <!-- Techniques will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let wsConnection = null;
        let testResults = [];

        // Load available techniques
        async function loadTechniques() {
            try {
                const response = await fetch('?action=get_techniques');
                const techniques = await response.json();
                displayTechniques(techniques);
            } catch (error) {
                console.error('Failed to load techniques:', error);
            }
        }

        // Display techniques
        function displayTechniques(techniques) {
            const container = document.getElementById('techniquesDisplay');
            let html = '';
            
            for (const [id, technique] of Object.entries(techniques)) {
                html += `
                    <div class="card technique-card mb-3">
                        <div class="card-header">
                            <h6>${technique.name}</h6>
                            <small class="text-muted">${technique.description}</small>
                        </div>
                        <div class="card-body">
                            <strong>Sample Payloads:</strong>
                            ${technique.payloads.map((payload, index) => `
                                <div class="payload-display mt-2">
                                    <small>Payload ${index + 1}:</small><br>
                                    <code>${Array.isArray(payload) ? JSON.stringify(payload) : payload}</code>
                                    <button class="btn btn-sm btn-outline-primary float-end" 
                                            onclick="testTechniquePayload('${id}', ${index})">
                                        Test
                                    </button>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            
            container.innerHTML = html;
        }

        // Test single message
        async function testSingleMessage() {
            const message = document.getElementById('customMessage').value;
            const frameType = document.getElementById('frameType').value;
            
            if (!message.trim()) {
                alert('Please enter a message to test');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('message', message);
                formData.append('frame_type', frameType);
                
                const response = await fetch('?action=test_message', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                displayTestResult('Single Message Test', message, result);
                
            } catch (error) {
                console.error('Test failed:', error);
                alert('Test failed: ' + error.message);
            }
        }

        // Test specific technique payload
        async function testTechniquePayload(techniqueId, payloadIndex) {
            try {
                const techniques = await (await fetch('?action=get_techniques')).json();
                const payload = techniques[techniqueId].payloads[payloadIndex];
                const payloadStr = Array.isArray(payload) ? JSON.stringify(payload) : payload;
                
                const formData = new FormData();
                formData.append('message', payloadStr);
                formData.append('frame_type', 'text');
                
                const response = await fetch('?action=test_message', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                displayTestResult(`${techniqueId} - Payload ${payloadIndex + 1}`, payloadStr, result);
                
            } catch (error) {
                console.error('Technique test failed:', error);
            }
        }

        // Run full evasion test
        async function runFullEvasionTest() {
            document.getElementById('testResults').innerHTML = '<div class="text-center p-4"><i class="fas fa-spinner fa-spin"></i> Running comprehensive evasion tests...</div>';
            
            try {
                const response = await fetch('?action=run_full_test');
                const results = await response.json();
                
                displayFullTestResults(results);
                
            } catch (error) {
                console.error('Full test failed:', error);
                alert('Full test failed: ' + error.message);
            }
        }

        // Display test result
        function displayTestResult(testName, payload, result) {
            const container = document.getElementById('testResults');
            
            let riskClass = 'risk-low';
            let riskBadge = 'success';
            
            if (result.security_risk === 'critical') {
                riskClass = 'risk-critical';
                riskBadge = 'danger';
            } else if (result.security_risk === 'high') {
                riskClass = 'risk-high';
                riskBadge = 'warning';
            } else if (result.security_risk === 'medium') {
                riskClass = 'risk-medium';
                riskBadge = 'info';
            }
            
            const resultHtml = `
                <div class="card technique-card ${riskClass} mb-3">
                    <div class="card-header">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6>${testName}</h6>
                            <span class="badge bg-${riskBadge}">${result.security_risk.toUpperCase()}</span>
                        </div>
                        <small class="text-muted">${new Date().toLocaleTimeString()}</small>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <strong>Payload:</strong>
                                <div class="payload-display">
                                    <code>${payload.substring(0, 200)}${payload.length > 200 ? '...' : ''}</code>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <strong>Analysis:</strong>
                                <ul>
                                    <li>Payload Detected: ${result.payload_detected ? '✅' : '❌'}</li>
                                    <li>Execution Possible: ${result.execution_possible ? '⚠️' : '✅'}</li>
                                    <li>Message Processed: ${result.message_processed ? '✅' : '❌'}</li>
                                    ${result.evasion_technique ? `<li>Evasion: ${result.evasion_technique}</li>` : ''}
                                    ${result.attack_types && result.attack_types.length > 0 ? `<li>Attacks: ${result.attack_types.join(', ')}</li>` : ''}
                                </ul>
                                ${result.decoded_payload && result.decoded_payload !== payload ? `
                                    <strong>Decoded:</strong>
                                    <div class="payload-display">
                                        <code>${JSON.stringify(result.decoded_payload).substring(0, 100)}...</code>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            if (container.innerHTML.includes('No tests run yet')) {
                container.innerHTML = resultHtml;
            } else {
                container.innerHTML = resultHtml + container.innerHTML;
            }
            
            testResults.push({
                timestamp: Date.now(),
                test_name: testName,
                payload: payload,
                result: result
            });
        }

        // Display full test results
        function displayFullTestResults(results) {
            const container = document.getElementById('testResults');
            let html = '<div class="mb-3"><h6>📊 Comprehensive Test Results</h6></div>';
            
            let totalTests = 0;
            let criticalFindings = 0;
            let evasionsSuccessful = 0;
            
            for (const [techniqueId, technique] of Object.entries(results)) {
                html += `
                    <div class="card technique-card mb-3">
                        <div class="card-header">
                            <h6>${technique.technique}</h6>
                            <small class="text-muted">${technique.description}</small>
                        </div>
                        <div class="card-body">
                `;
                
                for (const [testId, test] of Object.entries(technique.tests)) {
                    totalTests++;
                    
                    let testResult = test.standard_detection || test.text_frame_result;
                    if (testResult && testResult.security_risk === 'critical') {
                        criticalFindings++;
                    }
                    
                    if (testResult && !testResult.payload_detected && testResult.decoded_payload) {
                        evasionsSuccessful++;
                    }
                    
                    html += `
                        <div class="mb-2 p-2 border rounded">
                            <strong>Test ${testId}:</strong>
                            <div class="small">
                                Payload: <code>${Array.isArray(test.payload) ? JSON.stringify(test.payload) : test.payload.substring(0, 50)}...</code>
                            </div>
                            <div class="small">
                                Risk: <span class="badge bg-${testResult?.security_risk === 'critical' ? 'danger' : testResult?.security_risk === 'high' ? 'warning' : 'success'}">${testResult?.security_risk || 'unknown'}</span>
                                Detected: ${testResult?.payload_detected ? '❌' : '✅'}
                            </div>
                        </div>
                    `;
                }
                
                html += '</div></div>';
            }
            
            // Add summary
            const evasionRate = totalTests > 0 ? Math.round((evasionsSuccessful / totalTests) * 100) : 0;
            const summaryHtml = `
                <div class="alert alert-info">
                    <h6>📈 Test Summary</h6>
                    <ul class="mb-0">
                        <li>Total Tests: ${totalTests}</li>
                        <li>Critical Findings: ${criticalFindings}</li>
                        <li>Successful Evasions: ${evasionsSuccessful}</li>
                        <li>Evasion Rate: ${evasionRate}%</li>
                    </ul>
                    ${evasionRate > 70 ? '<div class="text-danger"><strong>⚠️ High evasion rate detected! Review WebSocket security controls.</strong></div>' : ''}
                </div>
            `;
            
            container.innerHTML = summaryHtml + html;
        }

        // Clear results
        function clearResults() {
            document.getElementById('testResults').innerHTML = '<div class="text-muted text-center p-4">No tests run yet. Use the control panel to start testing.</div>';
            testResults = [];
        }

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadTechniques();
        });
    </script>
</body>
</html>
