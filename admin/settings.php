<?php
session_start();
require_once '../config/database.php';
require_once '../includes/functions.php';

requireAdmin();

// Handle form submissions
if ($_POST) {
    $action = $_POST['action'] ?? '';

    try {
        switch ($action) {
            case 'update_site_settings':
                $siteName = $_POST['site_name'];
                $siteDescription = $_POST['site_description'];
                $allowRegistration = isset($_POST['allow_registration']) ? 1 : 0;
                $enableSearch = isset($_POST['enable_search']) ? 1 : 0;

                // In a real app, this would be stored in a settings table
                // For vulnerability demo, we'll just show the vulnerable behavior
                $success = "Pengaturan berhasil disimpan! (Vulnerable to XSS: $siteName)";
                break;

            case 'clear_logs':
                // Vulnerable - no authorization check beyond admin
                $logFile = '../logs/system.log';
                if (file_exists($logFile)) {
                    file_put_contents($logFile, '');
                }
                $success = "Log sistem berhasil dibersihkan!";
                break;

            case 'backup_database':
                // Vulnerable command injection possibility
                $backupName = $_POST['backup_name'] ?? 'forum_backup_' . date('Y-m-d');
                // This would be vulnerable to command injection in real scenario
                $success = "Backup database dimulai: " . htmlspecialchars($backupName);
                break;
        }
    } catch (Exception $e) {
        $error = "Error: " . $e->getMessage();
    }
}

// Get system information
$systemInfo = [
    'php_version' => phpversion(),
    'mysql_version' => $pdo->query("SELECT VERSION()")->fetchColumn(),
    'total_users' => getTotalUsers(),
    'total_posts' => getTotalPosts(),
    'disk_usage' => '15.2 MB', // Mock data
    'uptime' => '7 days, 3 hours'  // Mock data
];
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pengaturan - Admin Panel</title>
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
                            <a href="settings.php" class="nav-link active">
                                <i class="fas fa-cog"></i> Pengaturan
                            </a>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">
                        <i class="fas fa-cog"></i> Pengaturan Sistem
                    </h1>
                </div>

                <!-- Messages -->
                <?php if (isset($success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check"></i> <?php echo $success; /* Deliberately vulnerable to XSS */ ?>
                    </div>
                <?php endif; ?>

                <?php if (isset($error)): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <!-- Settings Tabs -->
                <ul class="nav nav-tabs" id="settingsTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="general-tab" data-bs-toggle="tab" data-bs-target="#general" type="button" role="tab">
                            <i class="fas fa-cog"></i> Umum
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab">
                            <i class="fas fa-shield-alt"></i> Keamanan
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="system-tab" data-bs-toggle="tab" data-bs-target="#system" type="button" role="tab">
                            <i class="fas fa-server"></i> Sistem
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="backup-tab" data-bs-toggle="tab" data-bs-target="#backup" type="button" role="tab">
                            <i class="fas fa-database"></i> Backup
                        </button>
                    </li>
                </ul>

                <div class="tab-content" id="settingsTabContent">
                    <!-- General Settings -->
                    <div class="tab-pane fade show active" id="general" role="tabpanel">
                        <div class="card mt-3">
                            <div class="card-header">
                                <h5><i class="fas fa-cog"></i> Pengaturan Umum</h5>
                            </div>
                            <div class="card-body">
                                <form method="POST">
                                    <input type="hidden" name="action" value="update_site_settings">

                                    <div class="mb-3">
                                        <label for="site_name" class="form-label">Nama Situs</label>
                                        <input type="text" class="form-control" id="site_name" name="site_name"
                                            value="Forum Masyarakat" required>
                                    </div>

                                    <div class="mb-3">
                                        <label for="site_description" class="form-label">Deskripsi Situs</label>
                                        <textarea class="form-control" id="site_description" name="site_description" rows="3">
Tempat berbagi, berdiskusi, dan bertukar informasi untuk kemajuan masyarakat.
                                        </textarea>
                                    </div>

                                    <div class="mb-3 form-check">
                                        <input type="checkbox" class="form-check-input" id="allow_registration"
                                            name="allow_registration" checked>
                                        <label class="form-check-label" for="allow_registration">
                                            Izinkan registrasi pengguna baru
                                        </label>
                                    </div>

                                    <div class="mb-3 form-check">
                                        <input type="checkbox" class="form-check-input" id="enable_search"
                                            name="enable_search" checked>
                                        <label class="form-check-label" for="enable_search">
                                            Aktifkan fungsi pencarian
                                        </label>
                                    </div>

                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save"></i> Simpan Pengaturan
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <!-- Security Settings -->
                    <div class="tab-pane fade" id="security" role="tabpanel">
                        <div class="card mt-3">
                            <div class="card-header">
                                <h5><i class="fas fa-shield-alt"></i> Pengaturan Keamanan</h5>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-warning">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    <strong>Peringatan:</strong> Sistem ini SENGAJA vulnerable untuk tujuan testing!
                                </div>

                                <h6>Status Vulnerability:</h6>
                                <ul class="list-group list-group-flush mb-3">
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        SQL Injection Protection
                                        <span class="badge bg-danger">Disabled</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        XSS Protection
                                        <span class="badge bg-danger">Disabled</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        CSRF Protection
                                        <span class="badge bg-danger">Disabled</span>
                                    </li>
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Input Validation
                                        <span class="badge bg-danger">Bypassed</span>
                                    </li>
                                </ul>

                                <div class="alert alert-info">
                                    <i class="fas fa-info-circle"></i>
                                    Untuk testing keamanan, vulnerabilities ini sengaja diaktifkan.
                                    Jangan gunakan di production!
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- System Info -->
                    <div class="tab-pane fade" id="system" role="tabpanel">
                        <div class="card mt-3">
                            <div class="card-header">
                                <h5><i class="fas fa-server"></i> Informasi Sistem</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6>Environment</h6>
                                        <table class="table table-sm">
                                            <tr>
                                                <td>PHP Version</td>
                                                <td><code><?php echo $systemInfo['php_version']; ?></code></td>
                                            </tr>
                                            <tr>
                                                <td>MySQL Version</td>
                                                <td><code><?php echo $systemInfo['mysql_version']; ?></code></td>
                                            </tr>
                                            <tr>
                                                <td>Web Server</td>
                                                <td><code><?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?></code></td>
                                            </tr>
                                        </table>
                                    </div>
                                    <div class="col-md-6">
                                        <h6>Statistics</h6>
                                        <table class="table table-sm">
                                            <tr>
                                                <td>Total Users</td>
                                                <td><span class="badge bg-primary"><?php echo $systemInfo['total_users']; ?></span></td>
                                            </tr>
                                            <tr>
                                                <td>Total Posts</td>
                                                <td><span class="badge bg-success"><?php echo $systemInfo['total_posts']; ?></span></td>
                                            </tr>
                                            <tr>
                                                <td>Disk Usage</td>
                                                <td><span class="badge bg-info"><?php echo $systemInfo['disk_usage']; ?></span></td>
                                            </tr>
                                        </table>
                                    </div>
                                </div>

                                <hr>

                                <div class="d-flex gap-2">
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="action" value="clear_logs">
                                        <button type="submit" class="btn btn-outline-warning btn-sm"
                                            onclick="return confirm('Hapus semua log sistem?')">
                                            <i class="fas fa-trash"></i> Clear Logs
                                        </button>
                                    </form>

                                    <button type="button" class="btn btn-outline-info btn-sm" onclick="checkUpdates()">
                                        <i class="fas fa-sync"></i> Check Updates
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Backup -->
                    <div class="tab-pane fade" id="backup" role="tabpanel">
                        <div class="card mt-3">
                            <div class="card-header">
                                <h5><i class="fas fa-database"></i> Backup & Restore</h5>
                            </div>
                            <div class="card-body">
                                <form method="POST">
                                    <input type="hidden" name="action" value="backup_database">

                                    <div class="mb-3">
                                        <label for="backup_name" class="form-label">Nama Backup</label>
                                        <input type="text" class="form-control" id="backup_name" name="backup_name"
                                            value="forum_backup_<?php echo date('Y-m-d'); ?>" required>
                                        <div class="form-text">Nama file backup (tanpa ekstensi)</div>
                                    </div>

                                    <div class="d-flex gap-2">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="fas fa-download"></i> Create Backup
                                        </button>

                                        <button type="button" class="btn btn-outline-success" onclick="uploadRestore()">
                                            <i class="fas fa-upload"></i> Restore from Backup
                                        </button>
                                    </div>
                                </form>

                                <hr>

                                <h6>Available Backups:</h6>
                                <div class="alert alert-light">
                                    <i class="fas fa-info-circle"></i>
                                    No backups found. Create your first backup above.
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
        function checkUpdates() {
            alert('Checking for updates... (Demo feature)');
        }

        function uploadRestore() {
            alert('Restore feature would be implemented here. (Demo)');
        }

        // XSS Demo - this would be vulnerable in real scenario
        function testXSS() {
            const userInput = prompt('Enter test input:');
            if (userInput) {
                document.body.innerHTML += '<div class="alert alert-info">User input: ' + userInput + '</div>';
            }
        }
    </script>
</body>

</html>