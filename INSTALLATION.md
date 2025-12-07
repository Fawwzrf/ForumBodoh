# 📦 PANDUAN INSTALASI FORUM MASYARAKAT

## 🚀 Instalasi Cepat (Rekomendasi)

### Metode 1: Setup Script Otomatis
```bash
# Navigasi ke direktori forum
cd c:\laragon\www\Musywar

# Jalankan setup otomatis
php setup_simple.php
```

Skrip ini akan:
- ✅ Membuat database `forum_masyarakat`
- ✅ Mengimport schema yang sudah disederhanakan
- ✅ Membuat user default dengan data sample
- ✅ Memverifikasi instalasi

---

## 🛠️ Instalasi Manual

### 1. Persiapan Environment

**Start Laragon:**
- Buka Laragon
- Klik "Start All" untuk menjalankan Apache dan MySQL
- Pastikan status menunjukkan "Apache" dan "MySQL" berjalan (warna hijau)

### 2. Setup Database

**Metode A: Via phpMyAdmin (GUI)**
```
1. Akses: http://localhost/phpmyadmin
2. Buat database baru: forum_masyarakat
3. Import file: database/schema_simple.sql
```

**Metode B: Via Command Line**
```bash
# Akses MySQL
mysql -u root -p

# Buat database
CREATE DATABASE forum_masyarakat;

# Import schema
SOURCE c:/laragon/www/Musywar/database/schema_simple.sql;
```

**⚠️ Penting:** Gunakan `schema_simple.sql`

### 3. Akses Forum
```
URL: http://localhost/Musywar
```

### 4. Login Default

**Akun yang tersedia:**
```
👨‍💼 Admin:
- Username: admin
- Password: password
- Akses: Full admin panel

👮‍♂️ Moderator:
- Username: moderator  
- Password: password
- Akses: Post moderation

👤 Regular Users:
- Username: john_doe / jane_smith / bob_wilson
- Password: password
- Akses: Basic forum features
```

---

## ✅ Verifikasi Instalasi

Jalankan script verifikasi untuk memastikan semua komponen berfungsi:
```bash
php verify_system.php
```

Script ini akan mengecek:
- ✅ Koneksi database
- ✅ User admin tersedia  
- ✅ File-file penting ada
- ✅ Functions dimuat dengan benar
- ✅ Sample data terinstal

---

## 🔧 Troubleshooting

### Database Connection Error
```bash
# Cek status MySQL di Laragon
# Restart MySQL jika perlu
# Pastikan tidak ada aplikasi lain yang menggunakan port 3306
```

### Permission Errors
```bash
# Pastikan folder dapat ditulis
# Cek konfigurasi Apache di Laragon
```

### Schema Import Gagal
```bash
# Gunakan schema_simple.sql bukan schema.sql
# Jalankan setup_simple.php sebagai alternatif
```

---

## 🎯 Memulai Testing

Setelah instalasi berhasil, ikuti panduan testing:

### 1. Baca Dokumentasi Testing
```bash
# Buka file panduan lengkap
TESTING_GUIDE.md
```

### 2. Interface Testing
```
# Akses testing interface via browser
http://localhost/Musywar/test-payloads.html
```

### 3. Automated Testing
```bash
# Jalankan script Python testing
python evasion_tester.py
```

### 4. Manual Testing Quick Start
```
1. Login sebagai admin
2. Test XSS di search box: <script>alert('XSS')</script>
3. Test SQLi di login: admin' OR '1'='1' --
4. Test CSRF di admin panel
```

---

## 📋 Struktur Database

**Database:** `forum_masyarakat`

**Tabel Utama:**
- `users` - Data pengguna dan roles
- `posts` - Postingan forum
- `replies` - Komentar/balasan
- `categories` - Kategori forum
- `votes` - Sistem voting
- `reports` - Sistem pelaporan
- `messages` - Pesan pribadi
- `notifications` - Notifikasi
- `user_sessions` - Manajemen sesi

**Sample Data:**
- 5 user dengan berbagai role
- 4 kategori forum
- 3 post dengan XSS payloads
- Sample replies dengan vulnerable content

---

## ⚠️ Peringatan Keamanan

### 🚨 HANYA UNTUK TESTING!

```
❌ JANGAN gunakan di production
❌ JANGAN deploy ke internet
❌ JANGAN gunakan di sistem nyata
✅ HANYA untuk learning/testing lokal
✅ HANYA di environment terkontrol
✅ HANYA untuk tujuan edukasi
```

### 🔐 Vulnerabilities yang Diimplementasi

**Intentional vulnerabilities:**
- Cross-Site Scripting (XSS)
- SQL Injection 
- Cross-Site Request Forgery (CSRF)
- Information Disclosure
- Session Management Issues
- Privilege Escalation
- Input Validation Bypass

### 📚 Referensi

- `README.md` - Overview proyek
- `TESTING_GUIDE.md` - Panduan testing lengkap
- `database/schema_simple.sql` - Schema database
- `verify_system.php` - Script verifikasi

---

**✅ Instalasi Selesai!**

Forum siap untuk vulnerability testing dan educational purposes.
3. Cek di halaman postingan apakah script tereksekusi

### SQL Injection Testing
1. Di halaman login, masukkan:
   ```
   Username: admin' OR '1'='1' -- 
   Password: anything
   ```
2. Di search box:
   ```
   ' UNION SELECT 1,2,3,4,user(),database() -- 
   ```

### CSRF Testing
1. Buat file HTML dengan form attack
2. Load file tersebut saat login ke forum
3. Cek apakah action berhasil tanpa konfirmasi

## Evasion Testing

### Manual Testing
1. Gunakan payloads di `test-payloads.html`
2. Copy payload yang sesuai
3. Test di berbagai input form

### Automated Testing
```python
# Install requirements
pip install requests

# Run evasion tester
python evasion_tester.py
```

## Monitoring dengan Snort/Suricata

### Setup Rules
1. Tambahkan rules yang diberikan ke file konfigurasi
2. Monitor traffic ke `http://localhost/Musywar`
3. Lihat apakah attack berhasil tanpa detection

### Expected Results
- XSS attacks berhasil tanpa detection
- SQL injection bypass filter
- CSRF attacks succeed
- Information disclosure vulnerabilities

## Troubleshooting

### Database Connection Error
```php
// Edit config/database.php
$servername = "127.0.0.1"; // atau "localhost"
$username = "root";
$password = ""; // atau password MySQL Anda
```

### Permission Issues
```bash
# Windows - run as Administrator
icacls "c:\laragon\www\Musywar\logs" /grant Everyone:F

# Atau via PHP
chmod("logs", 0777);
```

### Apache Issues
- Pastikan port 80 tidak digunakan aplikasi lain
- Restart Laragon jika perlu
- Cek error.log Apache

## Files Structure Check

Pastikan struktur file sesuai:
```
Musywar/
├── index.php ✓
├── login.php ✓
├── register.php ✓
├── post.php ✓
├── create-post.php ✓
├── search.php ✓
├── profile.php ✓
├── logout.php ✓
├── setup.php ✓
├── track.php ✓
├── test-payloads.html ✓
├── evasion_tester.py ✓
├── admin/
│   ├── index.php ✓
│   ├── users.php ✓
│   └── posts.php ✓
├── api/
│   └── stats.php ✓
├── config/
│   └── database.php ✓
├── includes/
│   └── functions.php ✓
├── database/
│   ├── schema_simple.sql ✓ (YANG DIGUNAKAN)
│   └── schema.sql (legacy, ada masalah syntax)
├── assets/
│   ├── css/style.css ✓
│   ├── js/main.js ✓
│   └── img/ ✓
└── logs/ ✓
```

---

## 🚨 Security Warning

### ⚠️ PERINGATAN PENTING ⚠️

**Sistem ini SENGAJA VULNERABLE untuk:**
- ✅ Penelitian keamanan web
- ✅ Testing IDS/IPS evasion
- ✅ Pembelajaran security concepts
- ✅ Vulnerability assessment training

### 🚫 JANGAN DIGUNAKAN UNTUK:
- ❌ Production environments
- ❌ Public deployment 
- ❌ Real user data
- ❌ Commercial purposes

---

## ✅ Testing Checklist

**Setup Verification:**
- [ ] Database terkoneksi dengan `schema_simple.sql`
- [ ] Login berhasil dengan akun default (admin/password)
- [ ] Semua file PHP dapat diakses tanpa error
- [ ] Admin panel accessible via /admin/

**Vulnerability Testing:**
- [ ] XSS payload tereksekusi di posts/search
- [ ] SQL injection berhasil bypass login
- [ ] CSRF attack berhasil tanpa token protection
- [ ] Information disclosure via error messages
- [ ] Session management vulnerabilities working

**Evasion Testing:**
- [ ] IDS/IPS rule evasion techniques functional
- [ ] Obfuscated payloads bypass detection
- [ ] Case variation and encoding working
- [ ] Comment injection techniques effective

**Advanced Testing:**
- [ ] Stored XSS persisten di database
- [ ] Blind SQL injection via search
- [ ] Privilege escalation via admin panel
- [ ] File inclusion vulnerabilities (jika ada)

---

**🎉 Happy Testing! 🔍🛡️**

Gunakan `TESTING_GUIDE.md` untuk panduan testing yang lebih detail.
