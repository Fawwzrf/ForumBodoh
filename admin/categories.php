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
            case 'create_category':
                $name = $_POST['name'];
                $description = $_POST['description'] ?? '';
                $icon = $_POST['icon'] ?? '';
                $color = $_POST['color'] ?? '#007bff';

                // Vulnerable insert - no prepared statements
                $query = "INSERT INTO categories (name, description, icon, color, sort_order) 
                         VALUES ('$name', '$description', '$icon', '$color', 0)";
                $pdo->exec($query);
                $success = "Kategori berhasil ditambahkan!";
                break;

            case 'update_category':
                $id = $_POST['id'];
                $name = $_POST['name'];
                $description = $_POST['description'] ?? '';
                $icon = $_POST['icon'] ?? '';
                $color = $_POST['color'] ?? '#007bff';

                // Vulnerable update - no prepared statements
                $query = "UPDATE categories 
                         SET name='$name', description='$description', icon='$icon', color='$color' 
                         WHERE id=$id";
                $pdo->exec($query);
                $success = "Kategori berhasil diperbarui!";
                break;

            case 'delete_category':
                $id = $_POST['id'];
                // Vulnerable delete - no prepared statements
                $query = "DELETE FROM categories WHERE id=$id";
                $pdo->exec($query);
                $success = "Kategori berhasil dihapus!";
                break;
        }
    } catch (Exception $e) {
        $error = "Error: " . $e->getMessage();
    }
}

// Get all categories
$categories = getAllCategories();
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kelola Kategori - Admin Panel</title>
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
                            <a href="categories.php" class="nav-link active">
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
            <div class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">
                        <i class="fas fa-list"></i> Kelola Kategori
                    </h1>
                    <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addCategoryModal">
                        <i class="fas fa-plus"></i> Tambah Kategori
                    </button>
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

                <!-- Categories List -->
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title mb-0">Daftar Kategori</h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($categories)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-folder-open fa-3x text-muted mb-3"></i>
                                <h5>Belum Ada Kategori</h5>
                                <p class="text-muted">Mulai dengan membuat kategori pertama!</p>
                                <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addCategoryModal">
                                    <i class="fas fa-plus"></i> Tambah Kategori
                                </button>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Nama</th>
                                            <th>Deskripsi</th>
                                            <th>Icon</th>
                                            <th>Warna</th>
                                            <th>Dibuat</th>
                                            <th>Aksi</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($categories as $category): ?>
                                            <tr>
                                                <td><?php echo $category['id']; ?></td>
                                                <td>
                                                    <strong><?php echo htmlspecialchars($category['name']); ?></strong>
                                                </td>
                                                <td>
                                                    <?php echo htmlspecialchars($category['description'] ?? '-'); ?>
                                                </td>
                                                <td>
                                                    <?php if ($category['icon']): ?>
                                                        <i class="<?php echo htmlspecialchars($category['icon']); ?>"
                                                            style="color: <?php echo htmlspecialchars($category['color']); ?>"></i>
                                                        <small class="text-muted ms-2"><?php echo htmlspecialchars($category['icon']); ?></small>
                                                    <?php else: ?>
                                                        <span class="text-muted">-</span>
                                                    <?php endif; ?>
                                                </td>
                                                <td>
                                                    <span class="badge" style="background-color: <?php echo htmlspecialchars($category['color']); ?>">
                                                        <?php echo htmlspecialchars($category['color']); ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <small class="text-muted">
                                                        <?php echo timeAgo($category['created_at']); ?>
                                                    </small>
                                                </td>
                                                <td>
                                                    <div class="btn-group btn-group-sm">
                                                        <button type="button" class="btn btn-outline-warning"
                                                            onclick="editCategory(<?php echo htmlspecialchars(json_encode($category)); ?>)">
                                                            <i class="fas fa-edit"></i>
                                                        </button>
                                                        <button type="button" class="btn btn-outline-danger"
                                                            onclick="deleteCategory(<?php echo $category['id']; ?>, '<?php echo htmlspecialchars($category['name']); ?>')">
                                                            <i class="fas fa-trash"></i>
                                                        </button>
                                                    </div>
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

    <!-- Add Category Modal -->
    <div class="modal fade" id="addCategoryModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="POST">
                    <input type="hidden" name="action" value="create_category">
                    <div class="modal-header">
                        <h5 class="modal-title">Tambah Kategori</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="name" class="form-label">Nama Kategori *</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label for="description" class="form-label">Deskripsi</label>
                            <textarea class="form-control" id="description" name="description" rows="3"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="icon" class="form-label">Icon Class (FontAwesome)</label>
                            <input type="text" class="form-control" id="icon" name="icon"
                                placeholder="fas fa-comments" value="fas fa-folder">
                        </div>
                        <div class="mb-3">
                            <label for="color" class="form-label">Warna</label>
                            <input type="color" class="form-control form-control-color" id="color" name="color" value="#007bff">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Batal</button>
                        <button type="submit" class="btn btn-primary">Tambah Kategori</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit Category Modal -->
    <div class="modal fade" id="editCategoryModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="POST" id="editCategoryForm">
                    <input type="hidden" name="action" value="update_category">
                    <input type="hidden" name="id" id="editId">
                    <div class="modal-header">
                        <h5 class="modal-title">Edit Kategori</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="editName" class="form-label">Nama Kategori *</label>
                            <input type="text" class="form-control" id="editName" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label for="editDescription" class="form-label">Deskripsi</label>
                            <textarea class="form-control" id="editDescription" name="description" rows="3"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="editIcon" class="form-label">Icon Class (FontAwesome)</label>
                            <input type="text" class="form-control" id="editIcon" name="icon" placeholder="fas fa-comments">
                        </div>
                        <div class="mb-3">
                            <label for="editColor" class="form-label">Warna</label>
                            <input type="color" class="form-control form-control-color" id="editColor" name="color">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Batal</button>
                        <button type="submit" class="btn btn-warning">Update Kategori</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function editCategory(category) {
            document.getElementById('editId').value = category.id;
            document.getElementById('editName').value = category.name;
            document.getElementById('editDescription').value = category.description || '';
            document.getElementById('editIcon').value = category.icon || '';
            document.getElementById('editColor').value = category.color || '#007bff';

            const modal = new bootstrap.Modal(document.getElementById('editCategoryModal'));
            modal.show();
        }

        function deleteCategory(id, name) {
            if (confirm(`Apakah Anda yakin ingin menghapus kategori "${name}"?`)) {
                // CSRF vulnerability - no token protection
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                <input type="hidden" name="action" value="delete_category">
                <input type="hidden" name="id" value="${id}">
            `;
                document.body.appendChild(form);
                form.submit();
            }
        }
    </script>
</body>

</html>