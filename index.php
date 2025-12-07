<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Check if user is logged in
$isLoggedIn = isset($_SESSION['user_id']);
$user = null;
if ($isLoggedIn) {
    $user = getUserById($_SESSION['user_id']);
}
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum Masyarakat - Beranda</title>
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
                        <a class="nav-link active" href="index.php">Beranda</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="categories.php">Kategori</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="latest.php">Terbaru</a>
                    </li>
                </ul>

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
        <!-- Welcome Section -->
        <div class="row">
            <div class="col-12">
                <div class="jumbotron bg-light p-4 rounded">
                    <h1 class="display-4">Selamat Datang di Forum Masyarakat</h1>
                    <p class="lead">Tempat berbagi, berdiskusi, dan bertukar informasi untuk kemajuan masyarakat.</p>
                    <?php if (!$isLoggedIn): ?>
                        <a class="btn btn-primary btn-lg" href="register.php" role="button">Bergabung Sekarang</a>
                    <?php else: ?>
                        <a class="btn btn-success btn-lg" href="create-post.php" role="button">Buat Postingan Baru</a>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-users text-primary"></i></h5>
                        <h3><?php echo getTotalUsers(); ?></h3>
                        <p class="card-text">Total Anggota</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-comments text-success"></i></h5>
                        <h3><?php echo getTotalPosts(); ?></h3>
                        <p class="card-text">Total Postingan</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-list text-info"></i></h5>
                        <h3><?php echo getTotalCategories(); ?></h3>
                        <p class="card-text">Total Kategori</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title"><i class="fas fa-clock text-warning"></i></h5>
                        <h3><?php echo getTodayPosts(); ?></h3>
                        <p class="card-text">Hari Ini</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Latest Posts -->
        <div class="row">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5><i class="fas fa-clock"></i> Postingan Terbaru</h5>
                        <a href="latest.php" class="btn btn-sm btn-outline-primary">Lihat Semua</a>
                    </div>
                    <div class="card-body">
                        <?php
                        $latestPosts = getLatestPosts(10);
                        if (empty($latestPosts)):
                        ?>
                            <p class="text-muted text-center py-4">Belum ada postingan. Jadilah yang pertama!</p>
                        <?php else: ?>
                            <?php foreach ($latestPosts as $post): ?>
                                <div class="d-flex mb-3 p-3 border-bottom">
                                    <div class="flex-shrink-0">
                                        <img src="assets/img/avatar-default.png" alt="Avatar" class="rounded-circle" width="50" height="50">
                                    </div>
                                    <div class="flex-grow-1 ms-3">
                                        <h6 class="mb-1">
                                            <a href="post.php?id=<?php echo $post['id']; ?>" class="text-decoration-none">
                                                <?php echo $post['title']; ?>
                                            </a>
                                        </h6>
                                        <p class="mb-1 text-muted small">
                                            oleh <strong><?php echo $post['username']; ?></strong>
                                            di <strong><?php echo $post['category_name']; ?></strong>
                                        </p>
                                        <p class="mb-1 text-muted small">
                                            <i class="fas fa-clock"></i> <?php echo timeAgo($post['created_at']); ?>
                                            <i class="fas fa-comments ms-2"></i> <?php echo $post['reply_count']; ?> balasan
                                        </p>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Sidebar -->
            <div class="col-lg-4">
                <!-- Categories -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h5><i class="fas fa-list"></i> Kategori Populer</h5>
                    </div>
                    <div class="card-body">
                        <?php
                        $categories = getPopularCategories(5);
                        foreach ($categories as $category):
                        ?>
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <a href="category.php?id=<?php echo $category['id']; ?>" class="text-decoration-none">
                                    <?php echo $category['name']; ?>
                                </a>
                                <span class="badge bg-secondary"><?php echo $category['post_count']; ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <!-- Online Users -->
                <?php if ($isLoggedIn): ?>
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-users"></i> Pengguna Online</h5>
                        </div>
                        <div class="card-body">
                            <?php
                            $onlineUsers = getOnlineUsers();
                            foreach ($onlineUsers as $onlineUser):
                            ?>
                                <div class="mb-2">
                                    <i class="fas fa-circle text-success" style="font-size: 8px;"></i>
                                    <a href="user-profile.php?id=<?php echo $onlineUser['id']; ?>" class="text-decoration-none ms-2">
                                        <?php echo $onlineUser['username']; ?>
                                    </a>
                                    <small class="text-muted ms-1">(<?php echo $onlineUser['role']; ?>)</small>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-dark text-light mt-5 py-4">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h5>Forum Masyarakat</h5>
                    <p>Platform diskusi untuk membangun masyarakat yang lebih baik.</p>
                </div>
                <div class="col-md-6 text-end">
                    <p>&copy; 2025 Forum Masyarakat. All rights reserved.</p>
                    <p>
                        <a href="privacy.php" class="text-light">Kebijakan Privasi</a> |
                        <a href="terms.php" class="text-light">Syarat & Ketentuan</a>
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="assets/js/main.js"></script>
</body>

</html>