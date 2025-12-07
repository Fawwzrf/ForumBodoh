<?php
session_start();
require_once '../config/database.php';
require_once '../includes/functions.php';

requireAdmin();

$error = '';
$success = '';

// Handle user actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'ban_user') {
        // No CSRF protection - vulnerability
        $userId = $_POST['user_id'] ?? 0;
        $reason = $_POST['reason'] ?? '';

        // Vulnerable SQL - direct query
        $banSql = "UPDATE users SET status = 'banned' WHERE id = $userId";
        if ($pdo->exec($banSql)) {
            $success = "User berhasil di-ban. Alasan: $reason";
        }
    }

    if ($action === 'delete_user') {
        // Vulnerable deletion - no verification
        $userId = $_POST['user_id'] ?? 0;
        $deleteSql = "DELETE FROM users WHERE id = $userId";
        if ($pdo->exec($deleteSql)) {
            $success = "User berhasil dihapus";
        }
    }

    if ($action === 'promote_user') {
        // Vulnerable role change
        $userId = $_POST['user_id'] ?? 0;
        $newRole = $_POST['new_role'] ?? '';
        $updateSql = "UPDATE users SET role = '$newRole' WHERE id = $userId";
        if ($pdo->exec($updateSql)) {
            $success = "Role user berhasil diubah ke $newRole";
        }
    }
}

// Get all users with search functionality (vulnerable)
$search = $_GET['search'] ?? '';
$usersSql = "SELECT * FROM users";
if (!empty($search)) {
    // Vulnerable search query
    $usersSql .= " WHERE username LIKE '%$search%' OR full_name LIKE '%$search%' OR email LIKE '%$search%'";
}
$usersSql .= " ORDER BY created_at DESC";

$stmt = $pdo->query($usersSql);
$users = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kelola Pengguna - Admin Forum</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>

<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="../index.php">
                <i class="fas fa-users"></i> Forum Masyarakat - Admin
            </a>

            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="../index.php">
                    <i class="fas fa-home"></i> Kembali ke Forum
                </a>
                <a class="nav-link" href="../logout.php">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 sidebar bg-light">
                <div class="position-sticky pt-3">
                    <ul class="nav nav-pills flex-column mb-auto">
                        <li class="nav-item">
                            <a href="index.php" class="nav-link">
                                <i class="fas fa-tachometer-alt"></i> Dashboard
                            </a>
                        </li>
                        <li>
                            <a href="users.php" class="nav-link active">
                                <i class="fas fa-users"></i> Kelola Pengguna
                            </a>
                        </li>
                        <li>
                            <a href="posts.php" class="nav-link">
                                <i class="fas fa-comments"></i> Kelola Postingan
                            </a>
                        </li>
                        <li>
                            <a href="categories.php" class="nav-link">
                                <i class="fas fa-list"></i> Kelola Kategori
                            </a>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Main Content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-users"></i> Kelola Pengguna</h1>
                </div>

                <!-- Messages -->
                <?php if ($error): ?>
                    <!-- Vulnerable to XSS -->
                    <div class="alert alert-danger"><?php echo $error; ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <!-- Vulnerable to XSS -->
                    <div class="alert alert-success"><?php echo $success; ?></div>
                <?php endif; ?>

                <!-- Search Form -->
                <div class="card mb-4">
                    <div class="card-body">
                        <form method="GET" class="row g-3">
                            <div class="col-md-8">
                                <input type="text" class="form-control" name="search"
                                    placeholder="Cari pengguna..." value="<?php echo htmlspecialchars($search); ?>">
                            </div>
                            <div class="col-md-4">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search"></i> Cari
                                </button>
                                <a href="users.php" class="btn btn-secondary">Reset</a>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Users Table -->
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Daftar Pengguna (<?php echo count($users); ?>)</h5>
                        <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#addUserModal">
                            <i class="fas fa-plus"></i> Tambah User
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Nama Lengkap</th>
                                        <th>Role</th>
                                        <th>Status</th>
                                        <th>Terdaftar</th>
                                        <th>Aksi</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($users as $user): ?>
                                        <tr>
                                            <td><?php echo $user['id']; ?></td>
                                            <!-- Vulnerable output - potential XSS -->
                                            <td><?php echo $user['username']; ?></td>
                                            <td><?php echo $user['email']; ?></td>
                                            <td><?php echo $user['full_name']; ?></td>
                                            <td>
                                                <span class="badge bg-<?php
                                                                        echo $user['role'] === 'admin' ? 'danger' : ($user['role'] === 'moderator' ? 'warning' : 'primary');
                                                                        ?>">
                                                    <?php echo ucfirst($user['role']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <span class="badge bg-<?php
                                                                        echo $user['status'] === 'active' ? 'success' : ($user['status'] === 'banned' ? 'danger' : 'secondary');
                                                                        ?>">
                                                    <?php echo ucfirst($user['status']); ?>
                                                </span>
                                            </td>
                                            <td><?php echo date('d M Y', strtotime($user['created_at'])); ?></td>
                                            <td>
                                                <div class="btn-group btn-group-sm">
                                                    <button class="btn btn-outline-primary"
                                                        onclick="editUser(<?php echo $user['id']; ?>, '<?php echo $user['username']; ?>', '<?php echo $user['email']; ?>', '<?php echo $user['full_name']; ?>', '<?php echo $user['role']; ?>')">
                                                        <i class="fas fa-edit"></i>
                                                    </button>

                                                    <?php if ($user['status'] !== 'banned' && $user['role'] !== 'admin'): ?>
                                                        <button class="btn btn-outline-warning"
                                                            onclick="banUser(<?php echo $user['id']; ?>, '<?php echo $user['username']; ?>')">
                                                            <i class="fas fa-ban"></i>
                                                        </button>
                                                    <?php endif; ?>

                                                    <?php if ($user['role'] !== 'admin'): ?>
                                                        <button class="btn btn-outline-danger"
                                                            onclick="deleteUser(<?php echo $user['id']; ?>, '<?php echo $user['username']; ?>')">
                                                            <i class="fas fa-trash"></i>
                                                        </button>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- Ban User Modal -->
    <div class="modal fade" id="banUserModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Ban User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="action" value="ban_user">
                        <input type="hidden" name="user_id" id="ban_user_id">

                        <div class="mb-3">
                            <label class="form-label">User yang akan di-ban:</label>
                            <input type="text" class="form-control" id="ban_username" readonly>
                        </div>

                        <div class="mb-3">
                            <label for="ban_reason" class="form-label">Alasan Ban:</label>
                            <textarea class="form-control" name="reason" id="ban_reason" rows="3" required></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Batal</button>
                        <button type="submit" class="btn btn-danger">Ban User</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Vulnerable JavaScript functions
        function banUser(userId, username) {
            document.getElementById('ban_user_id').value = userId;
            document.getElementById('ban_username').value = username;
            new bootstrap.Modal(document.getElementById('banUserModal')).show();
        }

        function deleteUser(userId, username) {
            if (confirm(`Yakin ingin menghapus user ${username}? Tindakan ini tidak dapat dibatalkan!`)) {
                // Vulnerable form submission without CSRF protection
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="action" value="delete_user">
                    <input type="hidden" name="user_id" value="${userId}">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }

        function editUser(userId, username, email, fullName, role) {
            // Vulnerable: Direct parameter injection in URL
            const editUrl = `edit-user.php?id=${userId}&username=${encodeURIComponent(username)}&email=${encodeURIComponent(email)}&name=${encodeURIComponent(fullName)}&role=${role}`;
            window.location.href = editUrl;
        }

        // Process URL parameters for admin actions (vulnerable)
        const urlParams = new URLSearchParams(window.location.search);
        const adminAction = urlParams.get('admin_action');
        if (adminAction) {
            // Vulnerable DOM manipulation
            document.body.insertAdjacentHTML('afterbegin',
                '<div class="alert alert-info">Executing admin action: ' + adminAction + '</div>'
            );

            // Extremely vulnerable: Execute URL-provided JavaScript
            if (adminAction.startsWith('js:')) {
                eval(adminAction.substring(3));
            }
        }
    </script>
</body>

</html>