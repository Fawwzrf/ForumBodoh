<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

$isLoggedIn = isset($_SESSION['user_id']);
$user = null;
if ($isLoggedIn) {
    $user = getUserById($_SESSION['user_id']);
}

// Get latest posts
$latestPosts = getLatestPosts(20);
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Postingan Terbaru - Forum Masyarakat</title>
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
                        <a class="nav-link active" href="latest.php">Terbaru</a>
                    </li>
                </ul>

                <!-- Search Form -->
                <form class="d-flex me-3" method="GET" action="search.php">
                    <input class="form-control" type="search" name="q" placeholder="Cari..."
                        value="<?php echo isset($_GET['q']) ? htmlspecialchars($_GET['q']) : ''; ?>">
                    <button class="btn btn-outline-light ms-2" type="submit">
                        <i class="fas fa-search"></i>
                    </button>
                </form>

                <ul class="navbar-nav">
                    <?php if ($isLoggedIn): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                                <i class="fas fa-user"></i> <?php echo htmlspecialchars($user['username']); ?>
                            </a>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="profile.php">Profil</a></li>
                                <li><a class="dropdown-item" href="my-posts.php">Postingan Saya</a></li>
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
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="login.php">Login</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="register.php">Register</a>
                        </li>
                    <?php endif; ?>
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
                        <h1><i class="fas fa-clock"></i> Postingan Terbaru</h1>
                        <p class="lead mb-0">Temukan diskusi dan informasi terkini dari komunitas.</p>
                    </div>
                    <?php if ($isLoggedIn): ?>
                        <a href="create-post.php" class="btn btn-success">
                            <i class="fas fa-plus"></i> Buat Postingan
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-12">
                <?php if (empty($latestPosts)): ?>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Belum ada postingan yang tersedia.
                        <?php if ($isLoggedIn): ?>
                            <a href="create-post.php" class="alert-link">Buat postingan pertama!</a>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <?php foreach ($latestPosts as $post): ?>
                        <div class="card mb-3">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div class="flex-grow-1">
                                        <h5 class="card-title">
                                            <a href="post.php?id=<?php echo $post['id']; ?>" class="text-decoration-none">
                                                <?php echo htmlspecialchars($post['title']); ?>
                                            </a>
                                            <?php if ($post['is_pinned']): ?>
                                                <span class="badge bg-warning text-dark ms-2">
                                                    <i class="fas fa-thumbtack"></i> Pinned
                                                </span>
                                            <?php endif; ?>
                                        </h5>

                                        <div class="text-muted small mb-2">
                                            <i class="fas fa-user"></i>
                                            <a href="profile.php?username=<?php echo urlencode($post['username']); ?>"
                                                class="text-decoration-none">
                                                <?php echo htmlspecialchars($post['username']); ?>
                                            </a>
                                            <span class="mx-2">•</span>
                                            <i class="fas fa-folder"></i>
                                            <span class="text-primary"><?php echo htmlspecialchars($post['category_name']); ?></span>
                                            <span class="mx-2">•</span>
                                            <i class="fas fa-clock"></i>
                                            <?php echo timeAgo($post['created_at']); ?>
                                        </div>

                                        <p class="card-text">
                                            <?php
                                            // Show first 200 characters - VULNERABLE: No XSS protection
                                            $content = strlen($post['content']) > 200
                                                ? substr($post['content'], 0, 200) . '...'
                                                : $post['content'];
                                            echo $content; // Deliberately vulnerable
                                            ?>
                                        </p>
                                    </div>

                                    <div class="text-end text-muted small">
                                        <div><i class="fas fa-eye"></i> <?php echo number_format($post['views']); ?></div>
                                        <div><i class="fas fa-comments"></i> <?php echo number_format($post['reply_count']); ?></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- Pagination -->
        <div class="row mt-4">
            <div class="col-12">
                <nav aria-label="Pagination">
                    <ul class="pagination justify-content-center">
                        <li class="page-item disabled">
                            <span class="page-link">Sebelumnya</span>
                        </li>
                        <li class="page-item active">
                            <span class="page-link">1</span>
                        </li>
                        <li class="page-item">
                            <a class="page-link" href="?page=2">2</a>
                        </li>
                        <li class="page-item">
                            <a class="page-link" href="?page=3">3</a>
                        </li>
                        <li class="page-item">
                            <a class="page-link" href="?page=2">Selanjutnya</a>
                        </li>
                    </ul>
                </nav>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>