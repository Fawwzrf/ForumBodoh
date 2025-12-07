<?php
session_start();
require_once '../config/database.php';
require_once '../includes/functions.php';

requireAdmin();

$error = '';
$success = '';

// Handle post actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'delete_post') {
        // No CSRF protection - vulnerability
        $postId = $_POST['post_id'] ?? 0;

        // Vulnerable SQL - direct deletion
        $deleteSql = "DELETE FROM posts WHERE id = $postId";
        if ($pdo->exec($deleteSql)) {
            $success = "Postingan berhasil dihapus";
        }
    }

    if ($action === 'hide_post') {
        $postId = $_POST['post_id'] ?? 0;
        $hideSql = "UPDATE posts SET status = 'hidden' WHERE id = $postId";
        if ($pdo->exec($hideSql)) {
            $success = "Postingan berhasil disembunyikan";
        }
    }

    if ($action === 'pin_post') {
        $postId = $_POST['post_id'] ?? 0;
        $pinSql = "UPDATE posts SET is_pinned = 1 WHERE id = $postId";
        if ($pdo->exec($pinSql)) {
            $success = "Postingan berhasil di-pin";
        }
    }
}

// Get all posts with filters (vulnerable)
$status = $_GET['status'] ?? '';
$category = $_GET['category'] ?? '';
$search = $_GET['search'] ?? '';

$postsSql = "SELECT p.*, u.username, u.full_name, c.name as category_name,
             (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) as reply_count
             FROM posts p 
             JOIN users u ON p.user_id = u.id 
             JOIN categories c ON p.category_id = c.id 
             WHERE 1=1";

// Vulnerable query building
if (!empty($status)) {
    $postsSql .= " AND p.status = '$status'";
}
if (!empty($category)) {
    $postsSql .= " AND c.name LIKE '%$category%'";
}
if (!empty($search)) {
    $postsSql .= " AND (p.title LIKE '%$search%' OR p.content LIKE '%$search%')";
}

$postsSql .= " ORDER BY p.is_pinned DESC, p.created_at DESC";

$stmt = $pdo->query($postsSql);
$posts = $stmt->fetchAll();

// Get categories for filter
$categoriesSql = "SELECT * FROM categories ORDER BY name";
$categoriesStmt = $pdo->query($categoriesSql);
$categories = $categoriesStmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kelola Postingan - Admin Forum</title>
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
                <a class="nav-link" href="../index.php">Kembali ke Forum</a>
                <a class="nav-link" href="../logout.php">Logout</a>
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
                            <a href="posts.php" class="nav-link active">
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
                    <h1 class="h2"><i class="fas fa-comments"></i> Kelola Postingan</h1>
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

                <!-- Filters -->
                <div class="card mb-4">
                    <div class="card-body">
                        <form method="GET" class="row g-3">
                            <div class="col-md-3">
                                <select class="form-select" name="status">
                                    <option value="">Semua Status</option>
                                    <option value="published" <?php echo $status === 'published' ? 'selected' : ''; ?>>Published</option>
                                    <option value="draft" <?php echo $status === 'draft' ? 'selected' : ''; ?>>Draft</option>
                                    <option value="hidden" <?php echo $status === 'hidden' ? 'selected' : ''; ?>>Hidden</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <select class="form-select" name="category">
                                    <option value="">Semua Kategori</option>
                                    <?php foreach ($categories as $cat): ?>
                                        <option value="<?php echo htmlspecialchars($cat['name']); ?>"
                                            <?php echo $category === $cat['name'] ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($cat['name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-4">
                                <input type="text" class="form-control" name="search"
                                    placeholder="Cari postingan..." value="<?php echo htmlspecialchars($search); ?>">
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-primary w-100">
                                    <i class="fas fa-search"></i> Filter
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Posts Table -->
                <div class="card">
                    <div class="card-header">
                        <h5>Daftar Postingan (<?php echo count($posts); ?>)</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Judul</th>
                                        <th>Penulis</th>
                                        <th>Kategori</th>
                                        <th>Status</th>
                                        <th>Balasan</th>
                                        <th>Tanggal</th>
                                        <th>Aksi</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($posts as $post): ?>
                                        <tr>
                                            <td><?php echo $post['id']; ?></td>
                                            <td>
                                                <?php if ($post['is_pinned']): ?>
                                                    <i class="fas fa-thumbtack text-warning" title="Pinned"></i>
                                                <?php endif; ?>
                                                <!-- Vulnerable output -->
                                                <a href="../post.php?id=<?php echo $post['id']; ?>" target="_blank">
                                                    <?php echo $post['title']; ?>
                                                </a>
                                            </td>
                                            <td><?php echo htmlspecialchars($post['username']); ?></td>
                                            <td><?php echo htmlspecialchars($post['category_name']); ?></td>
                                            <td>
                                                <span class="badge bg-<?php
                                                                        echo $post['status'] === 'published' ? 'success' : ($post['status'] === 'hidden' ? 'danger' : 'warning');
                                                                        ?>">
                                                    <?php echo ucfirst($post['status']); ?>
                                                </span>
                                            </td>
                                            <td><?php echo $post['reply_count']; ?></td>
                                            <td><?php echo date('d M Y', strtotime($post['created_at'])); ?></td>
                                            <td>
                                                <div class="dropdown">
                                                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle"
                                                        type="button" data-bs-toggle="dropdown">
                                                        Aksi
                                                    </button>
                                                    <ul class="dropdown-menu">
                                                        <li>
                                                            <a class="dropdown-item" href="../post.php?id=<?php echo $post['id']; ?>" target="_blank">
                                                                <i class="fas fa-eye"></i> Lihat
                                                            </a>
                                                        </li>
                                                        <li>
                                                            <a class="dropdown-item" href="edit-post.php?id=<?php echo $post['id']; ?>">
                                                                <i class="fas fa-edit"></i> Edit
                                                            </a>
                                                        </li>
                                                        <?php if (!$post['is_pinned']): ?>
                                                            <li>
                                                                <button class="dropdown-item" onclick="pinPost(<?php echo $post['id']; ?>)">
                                                                    <i class="fas fa-thumbtack"></i> Pin
                                                                </button>
                                                            </li>
                                                        <?php endif; ?>
                                                        <?php if ($post['status'] !== 'hidden'): ?>
                                                            <li>
                                                                <button class="dropdown-item" onclick="hidePost(<?php echo $post['id']; ?>)">
                                                                    <i class="fas fa-eye-slash"></i> Sembunyikan
                                                                </button>
                                                            </li>
                                                        <?php endif; ?>
                                                        <li>
                                                            <hr class="dropdown-divider">
                                                        </li>
                                                        <li>
                                                            <button class="dropdown-item text-danger" onclick="deletePost(<?php echo $post['id']; ?>)">
                                                                <i class="fas fa-trash"></i> Hapus
                                                            </button>
                                                        </li>
                                                    </ul>
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Vulnerable admin functions without CSRF protection
        function deletePost(postId) {
            if (confirm('Yakin ingin menghapus postingan ini?')) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="action" value="delete_post">
                    <input type="hidden" name="post_id" value="${postId}">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }

        function hidePost(postId) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
                <input type="hidden" name="action" value="hide_post">
                <input type="hidden" name="post_id" value="${postId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }

        function pinPost(postId) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.innerHTML = `
                <input type="hidden" name="action" value="pin_post">
                <input type="hidden" name="post_id" value="${postId}">
            `;
            document.body.appendChild(form);
            form.submit();
        }

        // Vulnerable bulk operations
        function bulkAction() {
            const action = document.getElementById('bulk_action').value;
            const checkboxes = document.querySelectorAll('input[name="post_ids[]"]:checked');

            if (checkboxes.length === 0) {
                alert('Pilih setidaknya satu postingan');
                return;
            }

            const postIds = Array.from(checkboxes).map(cb => cb.value);

            // Vulnerable: Direct execution without validation
            if (action === 'delete_all') {
                if (confirm(`Hapus ${postIds.length} postingan terpilih?`)) {
                    // Vulnerable bulk delete
                    window.location.href = `bulk-actions.php?action=delete&ids=${postIds.join(',')}`;
                }
            }
        }

        // Process dangerous URL parameters
        const params = new URLSearchParams(window.location.search);
        const dangerousParam = params.get('exec');
        if (dangerousParam) {
            // Extremely vulnerable: Execute arbitrary code from URL
            eval(atob(dangerousParam)); // Base64 decode and execute
        }
    </script>
</body>

</html>