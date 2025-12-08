<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Check if user is logged in
if (!isLoggedIn()) {
    header('Location: login.php?message=login_required');
    exit;
}

$message = '';
$error = '';

// Vulnerable: No CSRF protection - intentional for testing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = $_POST['title'] ?? '';
    $content = $_POST['content'] ?? '';
    $category_id = $_POST['category'] ?? '';

    // Basic validation (minimal)
    if (empty($title) || empty($content) || empty($category_id)) {
        $error = 'Semua field harus diisi!';
    } else {
        // Vulnerable: No sanitization - allows XSS storage
        // This is intentional for testing purposes
        $postId = createPost($title, $content, $category_id, $_SESSION['user_id']);

        if ($postId) {
            // Vulnerable: Redirect with unsanitized message
            header("Location: post.php?id=$postId&message=" . urlencode('Post berhasil dibuat!'));
            exit;
        } else {
            $error = 'Gagal membuat postingan. Silakan coba lagi.';
        }
    }
}

// Get categories for dropdown
$categories = getAllCategories();

// Get user info
$user = getUserById($_SESSION['user_id']);
?>
<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Buat Postingan Baru - Forum Masyarakat</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .navbar-brand {
            font-weight: bold;
            color: #2c3e50 !important;
        }

        .card {
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            border: none;
        }

        .form-control:focus {
            border-color: #3498db;
            box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
        }

        .btn-primary {
            background: linear-gradient(45deg, #3498db, #2980b9);
            border: none;
        }

        .btn-primary:hover {
            background: linear-gradient(45deg, #2980b9, #1f4e79);
        }

        .preview-area {
            min-height: 200px;
            border: 1px dashed #dee2e6;
            border-radius: 0.375rem;
            padding: 15px;
            background-color: #f8f9fa;
        }

        .vulnerability-note {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
            font-size: 0.9em;
        }
    </style>
</head>

<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-comments"></i> Forum Masyarakat
            </a>
            <div class="navbar-nav ms-auto">
                <div class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle text-white" href="#" role="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user"></i> <?php echo htmlspecialchars($user['username'] ?? 'User'); ?>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="profile.php">Profile</a></li>
                        <li><a class="dropdown-item" href="my-posts.php">Postingan Saya</a></li>
                        <li>
                            <hr class="dropdown-divider">
                        </li>
                        <li><a class="dropdown-item" href="logout.php">Logout</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <!-- Header -->
                <div class="card mb-4">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col">
                                <h4 class="mb-0"><i class="fas fa-plus-circle text-primary"></i> Buat Postingan Baru</h4>
                                <small class="text-muted">Bagikan pemikiran dan diskusi Anda dengan komunitas</small>
                            </div>
                            <div class="col-auto">
                                <a href="index.php" class="btn btn-outline-secondary">
                                    <i class="fas fa-arrow-left"></i> Kembali
                                </a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Vulnerability Warning for Educational Purposes -->
                <div class="vulnerability-note">
                    <strong>⚠️ EDUCATIONAL NOTE:</strong> Form ini sengaja vulnerable untuk keperluan pembelajaran:
                    <br>• Tidak ada CSRF protection
                    <br>• Tidak ada input sanitization (memungkinkan XSS)
                    <br>• Minimal validation
                </div>

                <!-- Messages -->
                <?php if ($error): ?>
                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                        <i class="fas fa-exclamation-triangle"></i> <?php echo $error; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <?php if ($message): ?>
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        <i class="fas fa-check-circle"></i> <?php echo $message; ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <!-- Create Post Form -->
                <div class="card">
                    <div class="card-body">
                        <!-- Vulnerable: No CSRF token - intentional for testing -->
                        <form method="POST" id="createPostForm">
                            <div class="row">
                                <div class="col-md-8">
                                    <!-- Title Input -->
                                    <div class="mb-3">
                                        <label for="title" class="form-label">
                                            <i class="fas fa-heading text-primary"></i> Judul Postingan *
                                        </label>
                                        <input type="text"
                                            class="form-control"
                                            id="title"
                                            name="title"
                                            placeholder="Masukkan judul postingan yang menarik..."
                                            value="<?php echo htmlspecialchars($_POST['title'] ?? ''); ?>"
                                            maxlength="200"
                                            required>
                                        <div class="form-text">
                                            <span id="titleCounter">0</span>/200 karakter
                                        </div>
                                    </div>

                                    <!-- Category Select -->
                                    <div class="mb-3">
                                        <label for="category" class="form-label">
                                            <i class="fas fa-tags text-primary"></i> Kategori *
                                        </label>
                                        <select class="form-select" id="category" name="category" required>
                                            <option value="">Pilih kategori...</option>
                                            <?php if (!empty($categories)): ?>
                                                <?php foreach ($categories as $cat): ?>
                                                    <option value="<?php echo $cat['id']; ?>"
                                                        <?php echo (isset($_POST['category']) && $_POST['category'] == $cat['id']) ? 'selected' : ''; ?>>
                                                        <?php echo htmlspecialchars($cat['name']); ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </select>
                                    </div>

                                    <!-- Content Textarea -->
                                    <div class="mb-3">
                                        <label for="content" class="form-label">
                                            <i class="fas fa-edit text-primary"></i> Konten Postingan *
                                        </label>
                                        <!-- Vulnerable: No input sanitization - allows XSS injection -->
                                        <textarea class="form-control"
                                            id="content"
                                            name="content"
                                            rows="10"
                                            placeholder="Tulis konten postingan Anda di sini... (HTML tags diizinkan)"
                                            required><?php echo ($_POST['content'] ?? ''); ?></textarea>
                                        <div class="form-text">
                                            <i class="fas fa-info-circle text-warning"></i>
                                            <span class="text-danger">Tips:</span> Anda bisa menggunakan HTML untuk formatting (bold, italic, link, dll.)
                                            <br>
                                            <small class="text-muted">Contoh: &lt;b&gt;tebal&lt;/b&gt;, &lt;i&gt;miring&lt;/i&gt;, &lt;a href="url"&gt;link&lt;/a&gt;</small>
                                            <br>
                                            <small class="text-warning">⚠️ XSS Testing: &lt;script&gt;alert('XSS')&lt;/script&gt;</small>
                                        </div>
                                    </div>

                                    <!-- Buttons -->
                                    <div class="d-flex gap-2">
                                        <button type="submit" class="btn btn-primary px-4">
                                            <i class="fas fa-paper-plane"></i> Publikasikan
                                        </button>
                                        <button type="button" class="btn btn-outline-info" onclick="showPreview()">
                                            <i class="fas fa-eye"></i> Preview
                                        </button>
                                        <button type="reset" class="btn btn-outline-secondary">
                                            <i class="fas fa-undo"></i> Reset
                                        </button>
                                    </div>
                                </div>

                                <div class="col-md-4">
                                    <!-- Preview Area -->
                                    <div class="card">
                                        <div class="card-header">
                                            <h6 class="mb-0"><i class="fas fa-eye"></i> Preview</h6>
                                        </div>
                                        <div class="card-body preview-area" id="previewArea">
                                            <p class="text-muted text-center">
                                                <i class="fas fa-info-circle"></i><br>
                                                Preview akan muncul di sini ketika Anda mengklik tombol Preview
                                            </p>
                                        </div>
                                    </div>

                                    <!-- Quick Tips -->
                                    <div class="card mt-3">
                                        <div class="card-header">
                                            <h6 class="mb-0"><i class="fas fa-lightbulb text-warning"></i> Tips Menulis</h6>
                                        </div>
                                        <div class="card-body">
                                            <ul class="list-unstyled small mb-0">
                                                <li><i class="fas fa-check text-success"></i> Gunakan judul yang menarik</li>
                                                <li><i class="fas fa-check text-success"></i> Pilih kategori yang tepat</li>
                                                <li><i class="fas fa-check text-success"></i> Tulis konten yang informatif</li>
                                                <li><i class="fas fa-check text-success"></i> Gunakan formatting HTML</li>
                                            </ul>
                                        </div>
                                    </div>

                                    <!-- XSS Testing Examples -->
                                    <div class="card mt-3">
                                        <div class="card-header bg-warning">
                                            <h6 class="mb-0"><i class="fas fa-bug"></i> XSS Testing Examples</h6>
                                        </div>
                                        <div class="card-body">
                                            <small class="text-muted">For security testing:</small>
                                            <div class="mt-2">
                                                <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                                                <br><br>
                                                <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
                                                <br><br>
                                                <code>&lt;svg onload=alert('XSS')&gt;</code>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- CSRF Attack Examples (Educational) -->
                <div class="card mt-4">
                    <div class="card-header bg-danger text-white">
                        <h6 class="mb-0"><i class="fas fa-shield-alt"></i> CSRF Testing Examples</h6>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">Contoh form HTML untuk CSRF attack pada endpoint ini:</p>
                        <pre class="bg-light p-3 rounded"><code>&lt;form action="http://localhost:8000/create-post.php" method="POST"&gt;
    &lt;input name="title" value="CSRF Attack Post"&gt;
    &lt;input name="content" value="&lt;script&gt;alert('CSRF+XSS')&lt;/script&gt;"&gt;
    &lt;input name="category" value="1"&gt;
    &lt;script&gt;document.forms[0].submit();&lt;/script&gt;
&lt;/form&gt;</code></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

    <!-- Vulnerable JavaScript (intentional for testing) -->
    <script>
        // Title character counter
        document.getElementById('title').addEventListener('input', function() {
            document.getElementById('titleCounter').textContent = this.value.length;
        });

        // Preview function (vulnerable to XSS)
        function showPreview() {
            const title = document.getElementById('title').value;
            const content = document.getElementById('content').value;
            const category = document.getElementById('category').selectedOptions[0]?.text || 'Tidak dipilih';

            // Vulnerable: Direct HTML injection without sanitization
            const previewHTML = `
                <div class="border-bottom pb-2 mb-2">
                    <h5>${title}</h5>
                    <small class="text-muted">Kategori: ${category}</small>
                </div>
                <div class="preview-content">
                    ${content}
                </div>
            `;

            document.getElementById('previewArea').innerHTML = previewHTML;
        }

        // Vulnerable: Process URL parameters for XSS testing
        const urlParams = new URLSearchParams(window.location.search);
        const xssTest = urlParams.get('xss');
        if (xssTest) {
            // Vulnerable: Direct execution of URL parameter
            document.body.innerHTML += xssTest;
        }

        // Auto-populate for testing (if parameters provided)
        window.addEventListener('load', function() {
            const params = new URLSearchParams(window.location.search);

            if (params.get('test_title')) {
                document.getElementById('title').value = decodeURIComponent(params.get('test_title'));
            }

            if (params.get('test_content')) {
                document.getElementById('content').value = decodeURIComponent(params.get('test_content'));
            }

            if (params.get('test_category')) {
                document.getElementById('category').value = params.get('test_category');
            }

            // Auto-submit for CSRF testing
            if (params.get('auto_submit') === 'true') {
                setTimeout(function() {
                    document.getElementById('createPostForm').submit();
                }, 1000);
            }
        });

        // Vulnerable: localStorage manipulation for persistent XSS
        if (localStorage.getItem('malicious_content')) {
            document.getElementById('content').value = localStorage.getItem('malicious_content');
        }
    </script>
</body>

</html>