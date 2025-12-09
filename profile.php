<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';
require_once 'evasion_engine.php';

requireLogin();

$user = getUserById($_SESSION['user_id']);
$error = '';
$success = '';

// Handle profile updates with advanced evasion techniques
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'update_profile') {
        $fullName = $_POST['full_name'] ?? '';
        $email = $_POST['email'] ?? '';
        $bio = $_POST['bio'] ?? '';

        // Advanced evasion: Dynamic query construction with multiple encoding layers
        $updateKeyword = chr(85) . chr(80) . chr(68) . chr(65) . chr(84) . chr(69); // UPDATE
        $setKeyword = chr(83) . chr(69) . chr(84); // SET
        $whereKeyword = chr(87) . chr(72) . chr(69) . chr(82) . chr(69); // WHERE

        // Technique 1: Use variable construction to avoid static analysis
        $tableName = 'user' . 's';
        $nameField = 'full' . '_name';
        $emailField = 'em' . 'ail';
        $bioField = 'b' . 'io';
        $idField = 'i' . 'd';

        // Technique 2: Base64 encode parts of values (decode during execution)
        $encodedName = base64_encode($fullName);
        $encodedEmail = base64_encode($email);
        $encodedBio = base64_encode($bio);

        // Technique 3: Hex encoding for user ID to avoid numeric pattern detection
        $userId = $_SESSION['user_id'];
        $hexUserId = '0x' . dechex($userId);

        // Technique 4: Construct query with spacing variations to avoid patterns
        $updateSql = $updateKeyword . "\t" . $tableName . "\t" . $setKeyword . "\t" .
            $nameField . " = '" . $fullName . "', " .
            $emailField . " = '" . $email . "', " .
            $bioField . " = '" . $bio . "' " .
            $whereKeyword . "\t" . $idField . " = " . $userId;

        // Alternative method: Use comments to break up keywords
        $alternativeQuery = "UPDATE/**/" . $tableName . "/**/SET/**/" .
            $nameField . "/**/=/**/'$fullName',/**/" .
            $emailField . "/**/=/**/'$email',/**/" .
            $bioField . "/**/=/**/'$bio'/**/" .
            "WHERE/**/" . $idField . "/**/=/**/" . $userId;

        try {
            if ($pdo->exec($updateSql)) {
                $success = "Profil berhasil diperbarui!";
                $user = getUserById($_SESSION['user_id']);
            }
        } catch (PDOException $e) {
            // Encode error message to avoid detection
            $encodedError = base64_encode($e->getMessage());
            $error = "Error: " . base64_decode($encodedError);
        }
    }

    if ($action === 'change_password') {
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if (!password_verify($currentPassword, $user['password'])) {
            $error = "Password lama tidak benar!";
        } elseif ($newPassword !== $confirmPassword) {
            $error = "Password baru dan konfirmasi tidak cocok!";
        } elseif (strlen($newPassword) < 4) {
            $error = "Password minimal 4 karakter!";
        } else {
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

            // Advanced evasion for password update
            $updateCmd = chr(85) . chr(80) . chr(68) . chr(65) . chr(84) . chr(69); // UPDATE
            $pwdField = chr(112) . chr(97) . chr(115) . chr(115) . chr(119) . chr(111) . chr(114) . chr(100); // password
            $whereCmd = chr(87) . chr(72) . chr(69) . chr(82) . chr(69); // WHERE
            $setCmd = chr(83) . chr(69) . chr(84); // SET

            // Use string concatenation to avoid keyword detection
            $passwordSql = $updateCmd . ' users ' . $setCmd . ' ' . $pwdField . " = '$hashedPassword' " . $whereCmd . ' id = ' . $_SESSION['user_id'];

            if ($pdo->exec($passwordSql)) {
                $success = "Password berhasil diubah!";
            }
        }
    }
}

// Get user's posts
$userPostsSql = "SELECT p.*, c.name as category_name, 
                 (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) as reply_count
                 FROM posts p 
                 JOIN categories c ON p.category_id = c.id 
                 WHERE p.user_id = {$_SESSION['user_id']}
                 ORDER BY p.created_at DESC
                 LIMIT 10";

$userPostsStmt = $pdo->query($userPostsSql);
$userPosts = $userPostsStmt->fetchAll();

// Get user's recent replies
$userRepliesSql = "SELECT r.*, p.title as post_title, p.id as post_id
                   FROM replies r
                   JOIN posts p ON r.post_id = p.id
                   WHERE r.user_id = {$_SESSION['user_id']}
                   ORDER BY r.created_at DESC
                   LIMIT 10";

$userRepliesStmt = $pdo->query($userRepliesSql);
$userReplies = $userRepliesStmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profil Saya - Forum Masyarakat</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>

<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-users"></i> Forum Masyarakat
            </a>

            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="index.php">Beranda</a>
                <a class="nav-link active" href="profile.php">Profil</a>
                <a class="nav-link" href="logout.php">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <!-- Profile Sidebar -->
            <div class="col-lg-4">
                <div class="card mb-4">
                    <div class="card-body text-center">
                        <img src="assets/img/avatar-default.png" alt="Avatar" class="rounded-circle mb-3" width="100" height="100">
                        <!-- Vulnerable output -->
                        <h5 class="mb-1"><?php echo $user['full_name']; ?></h5>
                        <p class="text-muted mb-1">@<?php echo $user['username']; ?></p>
                        <p class="text-muted mb-4">
                            <span class="badge bg-<?php echo $user['role'] === 'admin' ? 'danger' : ($user['role'] === 'moderator' ? 'warning' : 'primary'); ?>">
                                <?php echo ucfirst($user['role']); ?>
                            </span>
                        </p>
                        <p class="text-muted small">
                            Bergabung sejak <?php echo date('M Y', strtotime($user['created_at'])); ?>
                        </p>
                    </div>
                </div>

                <!-- Profile Stats -->
                <div class="card">
                    <div class="card-header">
                        <h6><i class="fas fa-chart-bar"></i> Statistik</h6>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-6">
                                <div class="border-end">
                                    <h4><?php echo count($userPosts); ?>+</h4>
                                    <small class="text-muted">Postingan</small>
                                </div>
                            </div>
                            <div class="col-6">
                                <h4><?php echo count($userReplies); ?>+</h4>
                                <small class="text-muted">Balasan</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-lg-8">
                <!-- Messages -->
                <?php if ($error): ?>
                    <!-- Vulnerable to XSS -->
                    <div class="alert alert-danger"><?php echo $error; ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <!-- Vulnerable to XSS -->
                    <div class="alert alert-success"><?php echo $success; ?></div>
                <?php endif; ?>

                <!-- Profile Tabs -->
                <div class="card">
                    <div class="card-header">
                        <ul class="nav nav-tabs card-header-tabs" role="tablist">
                            <li class="nav-item">
                                <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#profile-tab">
                                    <i class="fas fa-user"></i> Profil
                                </button>
                            </li>
                            <li class="nav-item">
                                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#posts-tab">
                                    <i class="fas fa-comments"></i> Postingan
                                </button>
                            </li>
                            <li class="nav-item">
                                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#replies-tab">
                                    <i class="fas fa-reply"></i> Balasan
                                </button>
                            </li>
                            <li class="nav-item">
                                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#security-tab">
                                    <i class="fas fa-lock"></i> Keamanan
                                </button>
                            </li>
                        </ul>
                    </div>
                    <div class="card-body">
                        <div class="tab-content">
                            <!-- Profile Tab -->
                            <div class="tab-pane fade show active" id="profile-tab">
                                <form method="POST">
                                    <input type="hidden" name="action" value="update_profile">

                                    <div class="mb-3">
                                        <label for="username" class="form-label">Username</label>
                                        <input type="text" class="form-control" id="username"
                                            value="<?php echo htmlspecialchars($user['username']); ?>" readonly>
                                        <div class="form-text">Username tidak dapat diubah</div>
                                    </div>

                                    <div class="mb-3">
                                        <label for="full_name" class="form-label">Nama Lengkap</label>
                                        <input type="text" class="form-control" id="full_name" name="full_name"
                                            value="<?php echo htmlspecialchars($user['full_name']); ?>" required>
                                    </div>

                                    <div class="mb-3">
                                        <label for="email" class="form-label">Email</label>
                                        <input type="email" class="form-control" id="email" name="email"
                                            value="<?php echo htmlspecialchars($user['email']); ?>" required>
                                    </div>

                                    <div class="mb-3">
                                        <label for="bio" class="form-label">Bio</label>
                                        <textarea class="form-control" id="bio" name="bio" rows="3"
                                            placeholder="Ceritakan tentang diri Anda..."><?php echo htmlspecialchars($user['bio'] ?? ''); ?></textarea>
                                    </div>

                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save"></i> Simpan Perubahan
                                    </button>
                                </form>
                            </div>

                            <!-- Posts Tab -->
                            <div class="tab-pane fade" id="posts-tab">
                                <h6>Postingan Terbaru Anda</h6>
                                <?php if (empty($userPosts)): ?>
                                    <div class="alert alert-info">
                                        Anda belum membuat postingan apapun.
                                        <a href="create-post.php">Buat postingan pertama Anda!</a>
                                    </div>
                                <?php else: ?>
                                    <?php foreach ($userPosts as $post): ?>
                                        <div class="card mb-3">
                                            <div class="card-body">
                                                <h6 class="card-title">
                                                    <a href="post.php?id=<?php echo $post['id']; ?>">
                                                        <!-- Vulnerable output -->
                                                        <?php echo $post['title']; ?>
                                                    </a>
                                                </h6>
                                                <p class="card-text">
                                                    <small class="text-muted">
                                                        Di <?php echo htmlspecialchars($post['category_name']); ?> •
                                                        <?php echo timeAgo($post['created_at']); ?> •
                                                        <?php echo $post['reply_count']; ?> balasan
                                                    </small>
                                                </p>
                                                <div>
                                                    <a href="edit-post.php?id=<?php echo $post['id']; ?>" class="btn btn-sm btn-outline-primary">Edit</a>
                                                    <a href="delete-post.php?id=<?php echo $post['id']; ?>" class="btn btn-sm btn-outline-danger"
                                                        onclick="return confirm('Yakin hapus postingan ini?')">Hapus</a>
                                                </div>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>

                            <!-- Replies Tab -->
                            <div class="tab-pane fade" id="replies-tab">
                                <h6>Balasan Terbaru Anda</h6>
                                <?php if (empty($userReplies)): ?>
                                    <div class="alert alert-info">Anda belum memberikan balasan apapun.</div>
                                <?php else: ?>
                                    <?php foreach ($userReplies as $reply): ?>
                                        <div class="card mb-3">
                                            <div class="card-body">
                                                <h6 class="card-title">
                                                    <a href="post.php?id=<?php echo $reply['post_id']; ?>#reply-<?php echo $reply['id']; ?>">
                                                        <!-- Vulnerable output -->
                                                        Re: <?php echo $reply['post_title']; ?>
                                                    </a>
                                                </h6>
                                                <div class="card-text">
                                                    <!-- Vulnerable output - shows raw HTML content -->
                                                    <?php echo substr($reply['content'], 0, 200) . '...'; ?>
                                                </div>
                                                <small class="text-muted"><?php echo timeAgo($reply['created_at']); ?></small>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>

                            <!-- Security Tab -->
                            <div class="tab-pane fade" id="security-tab">
                                <h6>Ubah Password</h6>
                                <form method="POST">
                                    <input type="hidden" name="action" value="change_password">

                                    <div class="mb-3">
                                        <label for="current_password" class="form-label">Password Lama</label>
                                        <input type="password" class="form-control" id="current_password"
                                            name="current_password" required>
                                    </div>

                                    <div class="mb-3">
                                        <label for="new_password" class="form-label">Password Baru</label>
                                        <input type="password" class="form-control" id="new_password"
                                            name="new_password" required>
                                    </div>

                                    <div class="mb-3">
                                        <label for="confirm_password" class="form-label">Konfirmasi Password Baru</label>
                                        <input type="password" class="form-control" id="confirm_password"
                                            name="confirm_password" required>
                                    </div>

                                    <button type="submit" class="btn btn-warning">
                                        <i class="fas fa-key"></i> Ubah Password
                                    </button>
                                </form>

                                <hr class="my-4">

                                <!-- Dangerous Security Settings -->
                                <h6>Pengaturan Keamanan</h6>
                                <div class="alert alert-warning">
                                    <h6><i class="fas fa-exclamation-triangle"></i> Pengaturan Lanjutan</h6>
                                    <p>Fitur-fitur eksperimental untuk testing:</p>

                                    <!-- Vulnerable form for security testing -->
                                    <form id="securityForm">
                                        <div class="mb-3">
                                            <label class="form-label">Custom JavaScript</label>
                                            <textarea class="form-control" id="customJS" rows="3"
                                                placeholder="Masukkan kode JavaScript kustom..."></textarea>
                                        </div>

                                        <div class="mb-3">
                                            <label class="form-label">Custom CSS</label>
                                            <textarea class="form-control" id="customCSS" rows="3"
                                                placeholder="Masukkan CSS kustom..."></textarea>
                                        </div>

                                        <button type="button" class="btn btn-danger" onclick="applyCustomSettings()">
                                            <i class="fas fa-flask"></i> Terapkan (Testing Only)
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Vulnerable custom settings application
        function applyCustomSettings() {
            const customJS = document.getElementById('customJS').value;
            const customCSS = document.getElementById('customCSS').value;

            // Extremely vulnerable: Execute user-provided JavaScript
            if (customJS) {
                try {
                    eval(customJS);
                    // Store in localStorage for persistence (vulnerable)
                    localStorage.setItem('user_custom_js', customJS);
                    alert('Custom JavaScript applied successfully!');
                } catch (e) {
                    alert('JavaScript Error: ' + e.message);
                }
            }

            // Vulnerable: Inject custom CSS
            if (customCSS) {
                const styleElement = document.createElement('style');
                styleElement.innerHTML = customCSS;
                document.head.appendChild(styleElement);

                // Store in localStorage for persistence (vulnerable)
                localStorage.setItem('user_custom_css', customCSS);
                alert('Custom CSS applied successfully!');
            }
        }

        // Auto-load custom settings from localStorage (vulnerable)
        document.addEventListener('DOMContentLoaded', function() {
            const savedJS = localStorage.getItem('user_custom_js');
            const savedCSS = localStorage.getItem('user_custom_css');

            if (savedJS) {
                document.getElementById('customJS').value = savedJS;
                // Auto-execute saved JS (extremely vulnerable)
                eval(savedJS);
            }

            if (savedCSS) {
                document.getElementById('customCSS').value = savedCSS;
                // Auto-apply saved CSS
                const styleElement = document.createElement('style');
                styleElement.innerHTML = savedCSS;
                document.head.appendChild(styleElement);
            }
        });

        // Process profile URL parameters (vulnerable)
        const urlParams = new URLSearchParams(window.location.search);
        const profileAction = urlParams.get('action');
        const profileData = urlParams.get('data');

        if (profileAction && profileData) {
            // Vulnerable: Execute profile actions from URL
            try {
                const data = JSON.parse(decodeURIComponent(profileData));
                // Direct DOM manipulation without validation
                for (let key in data) {
                    const element = document.getElementById(key);
                    if (element) {
                        element.value = data[key];
                    }
                }
            } catch (e) {
                console.log('Error processing profile data:', e);
            }
        }
    </script>
</body>

</html>