<?php
session_start();
require_once '../config/database.php';
require_once '../includes/functions.php';

requireAdmin();

$stats = [
    'total_users' => getTotalUsers(),
    'total_posts' => getTotalPosts(),
    'total_categories' => getTotalCategories(),
    'today_posts' => getTodayPosts(),
];

// Get recent activities
function getRecentActivities($limit = 10)
{
    global $pdo;
    $query = "SELECT 'post' as type, p.title as title, u.username, p.created_at
              FROM posts p JOIN users u ON p.user_id = u.id
              UNION ALL
              SELECT 'user' as type, CONCAT('User registered: ', u.username) as title, u.username, u.created_at
              FROM users u
              ORDER BY created_at DESC LIMIT $limit";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

$recentActivities = getRecentActivities();
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Forum Masyarakat</title>
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
                            <a href="index.php" class="nav-link active">
                                <i class="fas fa-tachometer-alt"></i> Dashboard
                            </a>
                        </li>
                        <li>
                            <a href="users.php" class="nav-link">
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
                        <li>
                            <a href="reports.php" class="nav-link">
                                <i class="fas fa-flag"></i> Laporan
                            </a>
                        </li>
                        <li>
                            <a href="settings.php" class="nav-link">
                                <i class="fas fa-cog"></i> Pengaturan
                            </a>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Main Content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-tachometer-alt"></i> Dashboard</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary">Export</button>
                        </div>
                    </div>
                </div>

                <!-- Statistics Cards -->
                <div class="row mb-4">
                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-primary text-white mb-4">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <div class="text-white-75 small">Total Pengguna</div>
                                        <div class="text-lg font-weight-bold"><?php echo $stats['total_users']; ?></div>
                                    </div>
                                    <div>
                                        <i class="fas fa-users fa-2x text-white-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-success text-white mb-4">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <div class="text-white-75 small">Total Postingan</div>
                                        <div class="text-lg font-weight-bold"><?php echo $stats['total_posts']; ?></div>
                                    </div>
                                    <div>
                                        <i class="fas fa-comments fa-2x text-white-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-info text-white mb-4">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <div class="text-white-75 small">Total Kategori</div>
                                        <div class="text-lg font-weight-bold"><?php echo $stats['total_categories']; ?></div>
                                    </div>
                                    <div>
                                        <i class="fas fa-list fa-2x text-white-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xl-3 col-md-6">
                        <div class="card bg-warning text-white mb-4">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <div class="text-white-75 small">Postingan Hari Ini</div>
                                        <div class="text-lg font-weight-bold"><?php echo $stats['today_posts']; ?></div>
                                    </div>
                                    <div>
                                        <i class="fas fa-clock fa-2x text-white-50"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Recent Activities -->
                <div class="row">
                    <div class="col-lg-8">
                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-chart-area me-1"></i>
                                Aktivitas Terbaru
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>Tipe</th>
                                                <th>Deskripsi</th>
                                                <th>User</th>
                                                <th>Waktu</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($recentActivities as $activity): ?>
                                                <tr>
                                                    <td>
                                                        <?php if ($activity['type'] == 'post'): ?>
                                                            <span class="badge bg-primary">Post</span>
                                                        <?php else: ?>
                                                            <span class="badge bg-success">User</span>
                                                        <?php endif; ?>
                                                    </td>
                                                    <!-- Vulnerable output - XSS possible -->
                                                    <td><?php echo $activity['title']; ?></td>
                                                    <td><?php echo htmlspecialchars($activity['username']); ?></td>
                                                    <td><?php echo timeAgo($activity['created_at']); ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-lg-4">
                        <!-- Quick Actions -->
                        <div class="card mb-4">
                            <div class="card-header">
                                <i class="fas fa-bolt me-1"></i>
                                Quick Actions
                            </div>
                            <div class="card-body">
                                <div class="d-grid gap-2">
                                    <a href="users.php?action=add" class="btn btn-primary">
                                        <i class="fas fa-user-plus"></i> Tambah User
                                    </a>
                                    <a href="categories.php?action=add" class="btn btn-success">
                                        <i class="fas fa-plus"></i> Tambah Kategori
                                    </a>
                                    <a href="posts.php" class="btn btn-info">
                                        <i class="fas fa-eye"></i> Moderasi Postingan
                                    </a>
                                    <a href="backup.php" class="btn btn-warning">
                                        <i class="fas fa-download"></i> Backup Database
                                    </a>
                                </div>
                            </div>
                        </div>

                        <!-- System Info -->
                        <div class="card">
                            <div class="card-header">
                                <i class="fas fa-server me-1"></i>
                                System Info
                            </div>
                            <div class="card-body">
                                <small class="text-muted">
                                    <strong>PHP Version:</strong> <?php echo phpversion(); ?><br>
                                    <strong>Server Software:</strong> <?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?><br>
                                    <strong>Database:</strong> MySQL<br>
                                    <strong>Upload Max:</strong> <?php echo ini_get('upload_max_filesize'); ?><br>
                                    <strong>Memory Limit:</strong> <?php echo ini_get('memory_limit'); ?>
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

    <!-- Vulnerable admin panel JavaScript -->
    <script>
        // Admin notification system (vulnerable to XSS)
        function showNotification(message, type = 'info') {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
            // Vulnerable - direct HTML insertion
            alertDiv.innerHTML = message + '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
            document.body.insertBefore(alertDiv, document.body.firstChild);
        }

        // Process admin messages from URL
        const urlParams = new URLSearchParams(window.location.search);
        const adminMsg = urlParams.get('admin_msg');
        if (adminMsg) {
            // Vulnerable to XSS
            showNotification(decodeURIComponent(adminMsg), 'info');
        }

        // Auto-refresh stats every 30 seconds
        setInterval(function() {
            // Vulnerable AJAX-like functionality
            const xhr = new XMLHttpRequest();
            xhr.open('GET', 'api/stats.php', true);
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4 && xhr.status === 200) {
                    // Vulnerable response processing
                    document.body.insertAdjacentHTML('beforeend', xhr.responseText);
                }
            };
            xhr.send();
        }, 30000);
    </script>
</body>

</html>