<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // No CSRF protection - vulnerability
    $username = $_POST['username'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $fullName = $_POST['full_name'] ?? '';

    // Basic validation (intentionally weak)
    if (empty($username) || empty($email) || empty($password) || empty($fullName)) {
        $error = 'Semua field harus diisi!';
    } elseif ($password !== $confirmPassword) {
        $error = 'Password dan konfirmasi password tidak cocok!';
    } elseif (strlen($password) < 4) {
        $error = 'Password minimal 4 karakter!';
    } else {
        // Check if username exists (vulnerable)
        $existingUser = getUserByUsername($username);
        if ($existingUser) {
            $error = 'Username sudah digunakan!';
        } else {
            // Create user (vulnerable to SQL injection)
            if (createUser($username, $email, $password, $fullName)) {
                $success = 'Registrasi berhasil! Silakan login.';
                setFlashMessage('Registrasi berhasil! Selamat datang di Forum Masyarakat.', 'success');
            } else {
                $error = 'Terjadi kesalahan saat mendaftar. Silakan coba lagi.';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Forum Masyarakat</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>

<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-header bg-success text-white text-center">
                        <h4><i class="fas fa-user-plus"></i> Registrasi</h4>
                    </div>
                    <div class="card-body">
                        <?php if ($error): ?>
                            <!-- Vulnerable to XSS -->
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>

                        <?php if ($success): ?>
                            <!-- Vulnerable to XSS -->
                            <div class="alert alert-success"><?php echo $success; ?></div>
                        <?php endif; ?>

                        <form method="POST">
                            <div class="mb-3">
                                <label for="full_name" class="form-label">Nama Lengkap</label>
                                <input type="text" class="form-control" id="full_name" name="full_name"
                                    value="<?php echo htmlspecialchars($_POST['full_name'] ?? ''); ?>" required>
                            </div>

                            <div class="mb-3">
                                <label for="username" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username" name="username"
                                    value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
                                <div class="form-text">Username hanya boleh mengandung huruf, angka, dan underscore.</div>
                            </div>

                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email"
                                    value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
                            </div>

                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                                <div class="form-text">Password minimal 4 karakter.</div>
                            </div>

                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">Konfirmasi Password</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                            </div>

                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="agree" required>
                                <label class="form-check-label" for="agree">
                                    Saya menyetujui <a href="terms.php">syarat dan ketentuan</a>
                                </label>
                            </div>

                            <button type="submit" class="btn btn-success w-100">Daftar</button>
                        </form>

                        <div class="text-center mt-3">
                            <p>Sudah punya akun? <a href="login.php">Login di sini</a></p>
                        </div>
                    </div>
                </div>

                <div class="text-center mt-3">
                    <a href="index.php" class="btn btn-link"><i class="fas fa-arrow-left"></i> Kembali ke Beranda</a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>