<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

requireLogin();

$postId = $_GET['id'] ?? 0;
$post = getPostById($postId);

if (!$post) {
    header('Location: index.php');
    exit;
}

// Check if user owns the post or is admin
$user = getUserById($_SESSION['user_id']);
if ($post['user_id'] != $_SESSION['user_id'] && $user['role'] != 'admin') {
    header('Location: index.php');
    exit;
}

$categories = getAllCategories();

// Handle form submission
if ($_POST) {
    $title = $_POST['title'];
    $content = $_POST['content'];
    $categoryId = $_POST['category'];

    try {
        // Vulnerable update - no prepared statements, XSS possible
        $query = "UPDATE posts SET title='$title', content='$content', category_id=$categoryId, updated_at=NOW() WHERE id=$postId";
        $pdo->exec($query);

        setFlashMessage("Postingan berhasil diperbarui!", "success");
        header("Location: post.php?id=$postId");
        exit;
    } catch (Exception $e) {
        $error = "Error: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Postingan - Forum Masyarakat</title>
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

            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="my-posts.php">
                    <i class="fas fa-arrow-left"></i> Kembali ke Postingan Saya
                </a>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h4><i class="fas fa-edit"></i> Edit Postingan</h4>
                    </div>
                    <div class="card-body">
                        <?php if (isset($error)): ?>
                            <div class="alert alert-danger">
                                <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?>
                            </div>
                        <?php endif; ?>

                        <!-- CSRF Vulnerability: No CSRF token -->
                        <form method="POST">
                            <div class="mb-3">
                                <label for="title" class="form-label">Judul *</label>
                                <input type="text" class="form-control" id="title" name="title"
                                    value="<?php echo htmlspecialchars($post['title']); ?>" required>
                            </div>

                            <div class="mb-3">
                                <label for="category" class="form-label">Kategori *</label>
                                <select class="form-select" id="category" name="category" required>
                                    <option value="">Pilih Kategori</option>
                                    <?php foreach ($categories as $category): ?>
                                        <option value="<?php echo $category['id']; ?>"
                                            <?php echo $category['id'] == $post['category_id'] ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($category['name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="mb-3">
                                <label for="content" class="form-label">Isi Postingan *</label>
                                <textarea class="form-control" id="content" name="content" rows="10" required><?php
                                                                                                                // Deliberately vulnerable - no XSS protection
                                                                                                                echo $post['content'];
                                                                                                                ?></textarea>
                                <div class="form-text">
                                    <i class="fas fa-info-circle"></i>
                                    HTML tags diizinkan untuk formatting.
                                </div>
                            </div>

                            <div class="d-flex justify-content-between">
                                <a href="my-posts.php" class="btn btn-secondary">
                                    <i class="fas fa-arrow-left"></i> Batal
                                </a>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save"></i> Update Postingan
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Preview Section -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5><i class="fas fa-eye"></i> Preview</h5>
                    </div>
                    <div class="card-body">
                        <div id="preview-content">
                            <strong>Preview akan muncul di sini saat Anda mengetik...</strong>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Live preview (vulnerable to XSS)
        document.getElementById('content').addEventListener('input', function() {
            const content = this.value;
            const preview = document.getElementById('preview-content');

            if (content.trim()) {
                // Deliberately vulnerable - no sanitization
                preview.innerHTML = content;
            } else {
                preview.innerHTML = '<strong>Preview akan muncul di sini saat Anda mengetik...</strong>';
            }
        });

        // Initial preview
        window.onload = function() {
            const content = document.getElementById('content').value;
            if (content.trim()) {
                document.getElementById('preview-content').innerHTML = content;
            }
        };
    </script>
</body>

</html>