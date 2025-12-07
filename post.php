<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

requireLogin();

$error = '';
$success = '';

// Get post details
$postId = $_GET['id'] ?? 0;
$post = getPostById($postId);

if (!$post) {
    header('Location: index.php');
    exit;
}

// Handle reply submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_reply'])) {
    // No CSRF protection - vulnerability
    $content = $_POST['content'] ?? '';

    if (empty($content)) {
        $error = 'Konten balasan tidak boleh kosong!';
    } else {
        // Vulnerable to XSS - no content filtering
        if (createReply($content, $postId, $_SESSION['user_id'])) {
            $success = 'Balasan berhasil ditambahkan!';
            // Refresh to show new reply
            header("Location: post.php?id=$postId#replies");
            exit;
        } else {
            $error = 'Terjadi kesalahan saat menambahkan balasan.';
        }
    }
}

// Get replies
$replies = getRepliesByPostId($postId);

// Update last activity
updateLastActivity($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($post['title']); ?> - Forum Masyarakat</title>
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
                    <li class="nav-item">
                        <a class="nav-link" href="profile.php">
                            <i class="fas fa-user"></i> <?php echo htmlspecialchars($_SESSION['username']); ?>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="logout.php">Logout</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <!-- Breadcrumb -->
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="index.php">Beranda</a></li>
                <li class="breadcrumb-item"><a href="category.php?id=<?php echo $post['category_id']; ?>"><?php echo htmlspecialchars($post['category_name']); ?></a></li>
                <li class="breadcrumb-item active" aria-current="page"><?php echo htmlspecialchars($post['title']); ?></li>
            </ol>
        </nav>

        <!-- Post Content -->
        <div class="card mb-4">
            <div class="card-header">
                <h3 class="mb-0"><?php echo $post['title']; // Vulnerable to XSS 
                                    ?></h3>
                <small class="text-muted">
                    oleh <strong><?php echo htmlspecialchars($post['username']); ?></strong>
                    pada <?php echo date('d M Y H:i', strtotime($post['created_at'])); ?>
                    di kategori <strong><?php echo htmlspecialchars($post['category_name']); ?></strong>
                </small>
            </div>
            <div class="card-body">
                <!-- Vulnerable output - allows XSS -->
                <?php echo $post['content']; ?>
            </div>
            <div class="card-footer">
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted">
                        <i class="fas fa-clock"></i> <?php echo timeAgo($post['created_at']); ?>
                        <i class="fas fa-comments ms-3"></i> <?php echo count($replies); ?> balasan
                    </small>
                    <div>
                        <?php if ($_SESSION['user_id'] == $post['user_id'] || $_SESSION['role'] == 'admin'): ?>
                            <a href="edit-post.php?id=<?php echo $post['id']; ?>" class="btn btn-sm btn-outline-primary">
                                <i class="fas fa-edit"></i> Edit
                            </a>
                            <a href="delete-post.php?id=<?php echo $post['id']; ?>" class="btn btn-sm btn-outline-danger"
                                onclick="return confirm('Yakin ingin menghapus postingan ini?')">
                                <i class="fas fa-trash"></i> Hapus
                            </a>
                        <?php endif; ?>
                        <button class="btn btn-sm btn-primary" onclick="document.getElementById('reply-form').scrollIntoView();">
                            <i class="fas fa-reply"></i> Balas
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Replies Section -->
        <div id="replies">
            <h4><i class="fas fa-comments"></i> Balasan (<?php echo count($replies); ?>)</h4>

            <?php if (empty($replies)): ?>
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i> Belum ada balasan. Jadilah yang pertama memberikan balasan!
                </div>
            <?php else: ?>
                <?php foreach ($replies as $reply): ?>
                    <div class="card mb-3">
                        <div class="card-body">
                            <div class="d-flex align-items-start">
                                <img src="assets/img/avatar-default.png" alt="Avatar" class="rounded-circle me-3" width="40" height="40">
                                <div class="flex-grow-1">
                                    <h6 class="mb-1"><?php echo htmlspecialchars($reply['full_name']); ?></h6>
                                    <small class="text-muted">@<?php echo htmlspecialchars($reply['username']); ?> • <?php echo timeAgo($reply['created_at']); ?></small>
                                    <div class="mt-2">
                                        <!-- Vulnerable output - allows XSS -->
                                        <?php echo $reply['content']; ?>
                                    </div>
                                </div>
                                <?php if ($_SESSION['user_id'] == $reply['user_id'] || $_SESSION['role'] == 'admin'): ?>
                                    <div class="dropdown">
                                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                            <i class="fas fa-ellipsis-v"></i>
                                        </button>
                                        <ul class="dropdown-menu">
                                            <li><a class="dropdown-item" href="edit-reply.php?id=<?php echo $reply['id']; ?>">
                                                    <i class="fas fa-edit"></i> Edit</a></li>
                                            <li><a class="dropdown-item text-danger" href="delete-reply.php?id=<?php echo $reply['id']; ?>"
                                                    onclick="return confirm('Yakin ingin menghapus balasan ini?')">
                                                    <i class="fas fa-trash"></i> Hapus</a></li>
                                        </ul>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Reply Form -->
        <div class="card mt-4" id="reply-form">
            <div class="card-header">
                <h5><i class="fas fa-reply"></i> Tambah Balasan</h5>
            </div>
            <div class="card-body">
                <?php if ($error): ?>
                    <!-- Vulnerable to XSS -->
                    <div class="alert alert-danger"><?php echo $error; ?></div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <!-- Vulnerable to XSS -->
                    <div class="alert alert-success"><?php echo $success; ?></div>
                <?php endif; ?>

                <form method="POST">
                    <div class="mb-3">
                        <label for="content" class="form-label">Balasan Anda</label>
                        <textarea class="form-control" id="content" name="content" rows="5"
                            placeholder="Tulis balasan Anda di sini..." required></textarea>
                        <div class="form-text">Anda dapat menggunakan HTML untuk memformat teks.</div>
                    </div>

                    <button type="submit" name="submit_reply" class="btn btn-primary">
                        <i class="fas fa-paper-plane"></i> Kirim Balasan
                    </button>
                    <a href="index.php" class="btn btn-secondary">
                        <i class="fas fa-arrow-left"></i> Kembali
                    </a>
                </form>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-dark text-light mt-5 py-4">
        <div class="container">
            <div class="text-center">
                <p>&copy; 2025 Forum Masyarakat. All rights reserved.</p>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

    <!-- Vulnerable JavaScript for XSS demonstration -->
    <script>
        // Search functionality (vulnerable to XSS)
        function searchForum() {
            const query = document.getElementById('search').value;
            if (query) {
                // Vulnerable - direct insertion without encoding
                document.getElementById('search-results').innerHTML = 'Mencari: ' + query;
                window.location.href = 'search.php?q=' + encodeURIComponent(query);
            }
        }

        // URL parameter processing (vulnerable)
        const urlParams = new URLSearchParams(window.location.search);
        const msg = urlParams.get('msg');
        if (msg) {
            // Vulnerable - direct DOM manipulation
            document.body.innerHTML += '<div class="alert alert-info">' + msg + '</div>';
        }
    </script>
</body>

</html>