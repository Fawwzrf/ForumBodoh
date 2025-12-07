# 🧪 Step-by-Step Vulnerability Testing

Mari kita test setiap vulnerability satu per satu untuk memastikan semuanya berfungsi.

## 🔍 Test 1: SQL Injection di Login

### Payload yang akan digunakan:
```
Username: admin' OR '1'='1' --
Password: anything
```

### Langkah testing:
1. Buka browser: http://localhost/Musywar/login.php
2. Masukkan payload di field username
3. Masukkan password sembarang
4. Klik Login
5. **Expected Result**: Berhasil login sebagai admin

### Jika tidak berhasil:
- Cek console browser untuk error SQL
- Error akan ditampilkan karena ada information disclosure

---

## 🔍 Test 2: XSS di Search

### Payload:
```html
<script>alert('XSS Test')</script>
```

### Langkah testing:
1. Buka: http://localhost/Musywar/search.php
2. Masukkan payload di search box
3. Submit search
4. **Expected Result**: Alert box muncul

---

## 🔍 Test 3: Stored XSS di Post

### Payload:
```html
<img src=x onerror="alert('Stored XSS')">
```

### Langkah testing:
1. Login dengan user biasa (john_doe/password)
2. Buat post baru
3. Masukkan payload di content
4. Submit post
5. **Expected Result**: Alert muncul saat melihat post

---

## 🔍 Test 4: CSRF Attack

### Langkah testing:
1. Login sebagai admin
2. Buat file HTML dengan form CSRF
3. Buka file tersebut
4. **Expected Result**: Action admin tereksekusi tanpa konfirmasi

---

## 📊 Quick Test Script

Jalankan script ini untuk test otomatis:
```bash
php verify_system.php
```
