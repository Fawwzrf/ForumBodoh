<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

$isLoggedIn = isset($_SESSION['user_id']);
$user = null;
if ($isLoggedIn) {
    $user = getUserById($_SESSION['user_id']);
}

// Get all categories with post counts
$categories = getPopularCategories(20); // Get all categories
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kategori - Forum Masyarakat</title>
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
                        <a class="nav-link active" href="categories.php">Kategori</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="latest.php">Terbaru</a>
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
                <h1><i class="fas fa-list"></i> Kategori Forum</h1>
                <p class="lead">Jelajahi diskusi berdasarkan kategori yang menarik bagi Anda.</p>

                <?php if ($isLoggedIn && $user['role'] == 'admin'): ?>
                    <div class="mb-3">
                        <a href="admin/categories.php" class="btn btn-primary">
                            <i class="fas fa-plus"></i> Kelola Kategori
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="row">
            <?php if (empty($categories)): ?>
                <div class="col-12">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i> Belum ada kategori yang tersedia.
                    </div>
                </div>
            <?php else: ?>
                <?php foreach ($categories as $category): ?>
                    <div class="col-md-6 col-lg-4 mb-4">
                        <div class="card h-100">
                            <div class="card-body">
                                <div class="d-flex align-items-center mb-3">
                                    <?php if ($category['icon']): ?>
                                        <i class="<?php echo htmlspecialchars($category['icon']); ?> fa-2x me-3"
                                            style="color: <?php echo htmlspecialchars($category['color']); ?>"></i>
                                    <?php else: ?>
                                        <i class="fas fa-folder fa-2x me-3 text-primary"></i>
                                    <?php endif; ?>
                                    <div>
                                        <h5 class="card-title mb-0">
                                            <?php echo htmlspecialchars($category['name']); ?>
                                        </h5>
                                        <small class="text-muted">
                                            <?php echo $category['post_count']; ?> postingan
                                        </small>
                                    </div>
                                </div>

                                <?php if ($category['description']): ?>
                                    <p class="card-text">
                                        <?php echo htmlspecialchars($category['description']); ?>
                                    </p>
                                <?php endif; ?>

                                <a href="search.php?category=<?php echo $category['id']; ?>"
                                    class="btn btn-outline-primary btn-sm">
                                    <i class="fas fa-eye"></i> Lihat Postingan
                                </a>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>