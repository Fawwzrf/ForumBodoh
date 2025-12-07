<?php
session_start();
require_once '../config/database.php';
require_once '../includes/functions.php';

requireAdmin();

// Get reports from database
function getAllReports()
{
    global $pdo;
    $query = "SELECT r.*, 
              reporter.username as reporter_name,
              reported_user.username as reported_user_name,
              p.title as post_title,
              reply.content as reply_content
              FROM reports r 
              LEFT JOIN users reporter ON r.reporter_id = reporter.id
              LEFT JOIN users reported_user ON r.user_id = reported_user.id
              LEFT JOIN posts p ON r.post_id = p.id
              LEFT JOIN replies reply ON r.reply_id = reply.id
              ORDER BY r.created_at DESC";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

// Handle report actions
if ($_POST) {
    $action = $_POST['action'] ?? '';
    $reportId = $_POST['report_id'] ?? 0;

    try {
        switch ($action) {
            case 'resolve':
                $query = "UPDATE reports SET status='resolved', reviewed_by={$_SESSION['user_id']}, reviewed_at=NOW() WHERE id=$reportId";
                $pdo->exec($query);
                $success = "Laporan telah diselesaikan!";
                break;

            case 'dismiss':
                $query = "UPDATE reports SET status='dismissed', reviewed_by={$_SESSION['user_id']}, reviewed_at=NOW() WHERE id=$reportId";
                $pdo->exec($query);
                $success = "Laporan telah ditolak!";
                break;

            case 'delete_reported_content':
                $postId = $_POST['post_id'] ?? 0;
                $replyId = $_POST['reply_id'] ?? 0;

                if ($postId) {
                    $pdo->exec("UPDATE posts SET status='hidden' WHERE id=$postId");
                }
                if ($replyId) {
                    $pdo->exec("UPDATE replies SET is_hidden=1 WHERE id=$replyId");
                }

                $pdo->exec("UPDATE reports SET status='resolved', reviewed_by={$_SESSION['user_id']}, reviewed_at=NOW() WHERE id=$reportId");
                $success = "Konten telah disembunyikan dan laporan diselesaikan!";
                break;
        }
    } catch (Exception $e) {
        $error = "Error: " . $e->getMessage();
    }
}

$reports = getAllReports();
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laporan - Admin Panel</title>
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
                            <a href="reports.php" class="nav-link active">
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
            <div class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">
                        <i class="fas fa-flag"></i> Kelola Laporan
                    </h1>
                </div>

                <!-- Messages -->
                <?php if (isset($success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check"></i> <?php echo htmlspecialchars($success); ?>
                    </div>
                <?php endif; ?>

                <?php if (isset($error)): ?>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>

                <!-- Reports List -->
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title mb-0">Daftar Laporan</h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($reports)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-check-circle fa-3x text-success mb-3"></i>
                                <h5>Tidak Ada Laporan</h5>
                                <p class="text-muted">Semua bersih! Tidak ada laporan yang perlu ditinjau.</p>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Pelapor</th>
                                            <th>Jenis</th>
                                            <th>Target</th>
                                            <th>Alasan</th>
                                            <th>Status</th>
                                            <th>Tanggal</th>
                                            <th>Aksi</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($reports as $report): ?>
                                            <tr class="<?php echo $report['status'] == 'pending' ? 'table-warning' : ''; ?>">
                                                <td><?php echo $report['id']; ?></td>
                                                <td>
                                                    <strong><?php echo htmlspecialchars($report['reporter_name']); ?></strong>
                                                </td>
                                                <td>
                                                    <?php if ($report['post_id']): ?>
                                                        <span class="badge bg-primary">Post</span>
                                                    <?php elseif ($report['reply_id']): ?>
                                                        <span class="badge bg-info">Reply</span>
                                                    <?php elseif ($report['user_id']): ?>
                                                        <span class="badge bg-warning">User</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <?php if ($report['post_title']): ?>
                                                        <small><?php echo htmlspecialchars(substr($report['post_title'], 0, 50)); ?>...</small>
                                                    <?php elseif ($report['reply_content']): ?>
                                                        <small><?php echo htmlspecialchars(substr($report['reply_content'], 0, 50)); ?>...</small>
                                                    <?php elseif ($report['reported_user_name']): ?>
                                                        <small>User: <?php echo htmlspecialchars($report['reported_user_name']); ?></small>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <span class="badge bg-secondary">
                                                        <?php echo htmlspecialchars($report['reason']); ?>
                                                    </span>
                                                    <?php if ($report['description']): ?>
                                                        <br><small class="text-muted">
                                                            <?php echo htmlspecialchars($report['description']); ?>
                                                        </small>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <?php if ($report['status'] == 'pending'): ?>
                                                        <span class="badge bg-warning">Pending</span>
                                                    <?php elseif ($report['status'] == 'resolved'): ?>
                                                        <span class="badge bg-success">Resolved</span>
                                                    <?php elseif ($report['status'] == 'dismissed'): ?>
                                                        <span class="badge bg-danger">Dismissed</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <small class="text-muted">
                                                        <?php echo timeAgo($report['created_at']); ?>
                                                    </small>
                                                </td>
                                                <td>
                                                    <?php if ($report['status'] == 'pending'): ?>
                                                        <div class="btn-group btn-group-sm">
                                                            <button type="button" class="btn btn-outline-success"
                                                                onclick="resolveReport(<?php echo $report['id']; ?>)">
                                                                <i class="fas fa-check"></i> Resolve
                                                            </button>
                                                            <button type="button" class="btn btn-outline-danger"
                                                                onclick="dismissReport(<?php echo $report['id']; ?>)">
                                                                <i class="fas fa-times"></i> Dismiss
                                                            </button>
                                                            <?php if ($report['post_id'] || $report['reply_id']): ?>
                                                                <button type="button" class="btn btn-outline-warning"
                                                                    onclick="hideContent(<?php echo $report['id']; ?>, <?php echo $report['post_id'] ?? 0; ?>, <?php echo $report['reply_id'] ?? 0; ?>)">
                                                                    <i class="fas fa-eye-slash"></i> Hide
                                                                </button>
                                                            <?php endif; ?>
                                                        </div>
                                                    <?php else: ?>
                                                        <span class="text-muted">-</span>
                                                    <?php endif; ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function resolveReport(reportId) {
            if (confirm('Tandai laporan ini sebagai selesai?')) {
                submitAction('resolve', reportId);
            }
        }

        function dismissReport(reportId) {
            if (confirm('Tolak laporan ini?')) {
                submitAction('dismiss', reportId);
            }
        }

        function hideContent(reportId, postId, replyId) {
            if (confirm('Sembunyikan konten yang dilaporkan dan tandai laporan sebagai selesai?')) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                <input type="hidden" name="action" value="delete_reported_content">
                <input type="hidden" name="report_id" value="${reportId}">
                <input type="hidden" name="post_id" value="${postId}">
                <input type="hidden" name="reply_id" value="${replyId}">
            `;
                document.body.appendChild(form);
                form.submit();
            }
        }

        function submitAction(action, reportId) {
            // CSRF vulnerability - no token protection
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
            <input type="hidden" name="action" value="${action}">
            <input type="hidden" name="report_id" value="${reportId}">
        `;
            document.body.appendChild(form);
            form.submit();
        }
    </script>
</body>

</html>