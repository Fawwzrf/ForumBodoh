<?php
session_start();
require_once 'config/database.php';
require_once 'includes/functions.php';

// Process search
$searchQuery = $_GET['q'] ?? '';
$results = [];

if (!empty($searchQuery)) {
    // Vulnerable search - no input sanitization
    $results = searchPosts($searchQuery);
}
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pencarian: <?php echo htmlspecialchars($searchQuery); ?> - Forum Masyarakat</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>

<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-users"></i> Forum Masyarakat
            </a>

            <!-- Search form in navbar -->
            <div class="d-flex ms-auto">
                <form class="d-flex me-3" method="GET">
                    <input class="form-control" type="search" name="q" placeholder="Cari postingan..."
                        value="<?php echo htmlspecialchars($searchQuery); ?>" aria-label="Search">
                    <button class="btn btn-outline-light" type="submit">
                        <i class="fas fa-search"></i>
                    </button>
                </form>

                <?php if (isset($_SESSION['user_id'])): ?>
                    <a class="btn btn-light" href="profile.php">
                        <i class="fas fa-user"></i> <?php echo htmlspecialchars($_SESSION['username']); ?>
                    </a>
                <?php else: ?>
                    <a class="btn btn-light" href="login.php">Login</a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <!-- Search Results Header -->
                <div class="card mb-4">
                    <div class="card-body">
                        <?php if (empty($searchQuery)): ?>
                            <h4><i class="fas fa-search"></i> Pencarian</h4>
                            <p class="text-muted">Masukkan kata kunci untuk mencari postingan di forum.</p>

                            <!-- Advanced Search Form -->
                            <form method="GET" class="mt-4">
                                <div class="row">
                                    <div class="col-md-8">
                                        <input type="text" class="form-control" name="q" placeholder="Kata kunci pencarian..." required>
                                    </div>
                                    <div class="col-md-4">
                                        <button type="submit" class="btn btn-primary w-100">
                                            <i class="fas fa-search"></i> Cari
                                        </button>
                                    </div>
                                </div>
                            </form>
                        <?php else: ?>
                            <h4><i class="fas fa-search"></i> Hasil Pencarian</h4>
                            <!-- Vulnerable output - XSS possible -->
                            <p>Menampilkan hasil untuk: <strong><?php echo $searchQuery; ?></strong></p>
                            <p class="text-muted">Ditemukan <?php echo count($results); ?> hasil</p>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Search Results -->
                <?php if (!empty($searchQuery)): ?>
                    <?php if (empty($results)): ?>
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle"></i>
                            Tidak ditemukan postingan yang cocok dengan kata kunci "<?php echo htmlspecialchars($searchQuery); ?>".
                            <br>Coba gunakan kata kunci yang berbeda atau lebih umum.
                        </div>
                    <?php else: ?>
                        <div class="row">
                            <?php foreach ($results as $post): ?>
                                <div class="col-12 mb-4">
                                    <div class="card">
                                        <div class="card-body">
                                            <h5 class="card-title">
                                                <a href="post.php?id=<?php echo $post['id']; ?>" class="text-decoration-none">
                                                    <!-- Vulnerable - highlights search terms without proper escaping -->
                                                    <?php
                                                    $highlightedTitle = str_ireplace($searchQuery, '<mark>' . $searchQuery . '</mark>', $post['title']);
                                                    echo $highlightedTitle;
                                                    ?>
                                                </a>
                                            </h5>

                                            <div class="card-text mb-2">
                                                <!-- Vulnerable content preview with search highlighting -->
                                                <?php
                                                $preview = substr(strip_tags($post['content']), 0, 200) . '...';
                                                $highlightedPreview = str_ireplace($searchQuery, '<mark>' . $searchQuery . '</mark>', $preview);
                                                echo $highlightedPreview;
                                                ?>
                                            </div>

                                            <small class="text-muted">
                                                <i class="fas fa-user"></i> <?php echo htmlspecialchars($post['username']); ?>
                                                <i class="fas fa-folder ms-2"></i> <?php echo htmlspecialchars($post['category_name']); ?>
                                                <i class="fas fa-clock ms-2"></i> <?php echo timeAgo($post['created_at']); ?>
                                            </small>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- Search Tips -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h5><i class="fas fa-lightbulb"></i> Tips Pencarian</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Pencarian Efektif:</h6>
                                <ul>
                                    <li>Gunakan kata kunci yang spesifik</li>
                                    <li>Coba variasi kata yang berbeda</li>
                                    <li>Gunakan tanda kutip untuk pencarian exact match</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6>Contoh Pencarian:</h6>
                                <ul>
                                    <li><code>"teknologi informasi"</code> - exact match</li>
                                    <li><code>javascript tutorial</code> - beberapa kata</li>
                                    <li><code>belajar programming</code> - kata umum</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

    <!-- Vulnerable JavaScript for additional XSS vectors -->
    <script>
        // Process URL parameters for suggestions (vulnerable)
        const urlParams = new URLSearchParams(window.location.search);
        const suggestion = urlParams.get('suggestion');
        if (suggestion) {
            // Vulnerable DOM manipulation
            document.body.insertAdjacentHTML('afterbegin',
                '<div class="alert alert-info">Mencoba saran: ' + suggestion + '</div>'
            );
        }

        // Search suggestions function (vulnerable)
        function showSuggestion(query) {
            if (query.length > 2) {
                // Vulnerable AJAX request simulation
                document.getElementById('search-suggestions').innerHTML =
                    '<div class="list-group-item">Pencarian untuk: ' + query + '</div>';
            }
        }

        // Auto-complete functionality (vulnerable)
        function handleSearchInput(event) {
            const query = event.target.value;
            // Vulnerable - direct DOM insertion
            if (query.includes('<')) {
                document.body.insertAdjacentHTML('afterbegin', query);
            }
        }

        // Bind events
        const searchInput = document.querySelector('input[name="q"]');
        if (searchInput) {
            searchInput.addEventListener('input', handleSearchInput);
        }
    </script>
</body>

</html>