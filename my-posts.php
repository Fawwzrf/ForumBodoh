<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

requireLogin();
$user = getUserById($_SESSION['user_id']);

// Get user's posts
function getUserPosts($userId, $limit = 20)
{
    global $pdo;
    // Vulnerable query - no prepared statements
    $query = "SELECT p.*, c.name as category_name, 
              (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) as reply_count
              FROM posts p 
              JOIN categories c ON p.category_id = c.id 
              WHERE p.user_id = $userId
              ORDER BY p.created_at DESC LIMIT $limit";
    $stmt = $pdo->query($query);
    return $stmt->fetchAll();
}

$userPosts = getUserPosts($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Postingan Saya - Forum Masyarakat</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>

<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-users"></i> Forum Masyarakat
            </a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="index.php">Beranda</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="categories.php">Kategori</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="latest.php">Terbaru</a>
                    </li>
                </ul>

                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user"></i> <?php echo htmlspecialchars($user['username']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php">Profil</a></li>
                            <li><a class="dropdown-item active" href="my-posts.php">Postingan Saya</a></li>
                            <?php if ($user['role'] == 'admin'): ?>
                                <li>
                                    <hr class="dropdown-divider">
                                </li>
                                <li><a class="dropdown-item" href="admin/">Admin Panel</a></li>
                            <?php endif; ?>
                            <li>
                                <hr class="dropdown-divider">
                            </li>
                            <li><a class="dropdown-item" href="logout.php">Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h1><i class="fas fa-edit"></i> Postingan Saya</h1>
                        <p class="lead mb-0">Kelola semua postingan yang telah Anda buat.</p>
                    </div>
                    <a href="create-post.php" class="btn btn-success">
                        <i class="fas fa-plus"></i> Buat Postingan Baru
                    </a>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <?php if (empty($userPosts)): ?>
                    <div class="alert alert-info text-center">
                        <i class="fas fa-info-circle fa-2x mb-3"></i>
                        <h5>Anda belum membuat postingan</h5>
                        <p class="mb-3">Mulai berbagi pemikiran dan ide Anda dengan komunitas!</p>
                        <a href="create-post.php" class="btn btn-primary">
                            <i class="fas fa-plus"></i> Buat Postingan Pertama
                        </a>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th>Judul</th>
                                    <th>Kategori</th>
                                    <th>Status</th>
                                    <th>Views</th>
                                    <th>Replies</th>
                                    <th>Dibuat</th>
                                    <th>Aksi</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($userPosts as $post): ?>
                                    <tr>
                                        <td>
                                            <a href="post.php?id=<?php echo $post['id']; ?>"
                                                class="text-decoration-none fw-bold">
                                                <?php echo htmlspecialchars($post['title']); ?>
                                            </a>
                                            <?php if ($post['is_pinned']): ?>
                                                <span class="badge bg-warning text-dark ms-2">
                                                    <i class="fas fa-thumbtack"></i>
                                                </span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <span class="badge bg-primary">
                                                <?php echo htmlspecialchars($post['category_name']); ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if ($post['status'] == 'published'): ?>
                                                <span class="badge bg-success">Published</span>
                                            <?php elseif ($post['status'] == 'draft'): ?>
                                                <span class="badge bg-secondary">Draft</span>
                                            <?php else: ?>
                                                <span class="badge bg-danger">Hidden</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-eye text-muted"></i>
                                            <?php echo number_format($post['views']); ?>
                                        </td>
                                        <td>
                                            <i class="fas fa-comments text-muted"></i>
                                            <?php echo number_format($post['reply_count']); ?>
                                        </td>
                                        <td class="text-muted small">
                                            <?php echo timeAgo($post['created_at']); ?>
                                        </td>
                                        <td>
                                            <div class="btn-group btn-group-sm">
                                                <a href="post.php?id=<?php echo $post['id']; ?>"
                                                    class="btn btn-outline-primary" title="Lihat">
                                                    <i class="fas fa-eye"></i>
                                                </a>
                                                <a href="edit-post.php?id=<?php echo $post['id']; ?>"
                                                    class="btn btn-outline-warning" title="Edit">
                                                    <i class="fas fa-edit"></i>
                                                </a>
                                                <button type="button" class="btn btn-outline-danger"
                                                    onclick="deletePost(<?php echo $post['id']; ?>)" title="Hapus">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <!-- Summary -->
                    <div class="row mt-4">
                        <div class="col-12">
                            <div class="alert alert-light">
                                <strong>Total Postingan: </strong><?php echo count($userPosts); ?> postingan
                                <span class="ms-3">
                                    <strong>Total Views: </strong><?php echo number_format(array_sum(array_column($userPosts, 'views'))); ?>
                                </span>
                                <span class="ms-3">
                                    <strong>Total Replies: </strong><?php echo number_format(array_sum(array_column($userPosts, 'reply_count'))); ?>
                                </span>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function deletePost(postId) {
            if (confirm('Apakah Anda yakin ingin menghapus postingan ini?')) {
                // CSRF vulnerability - no token validation
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = 'delete-post.php';
                form.innerHTML = `<input type="hidden" name="post_id" value="${postId}">`;
                document.body.appendChild(form);
                form.submit();
            }
        }
    </script>
</body>

</html>