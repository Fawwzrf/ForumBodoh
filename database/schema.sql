CREATE DATABASE IF NOT EXISTS forum_masyarakat;

USE forum_masyarakat;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role ENUM('user', 'moderator', 'admin') DEFAULT 'user',
    status ENUM(
        'active',
        'inactive',
        'banned'
    ) DEFAULT 'active',
    avatar VARCHAR(255) DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    login_attempts INT DEFAULT 0,
    reset_token VARCHAR(255) DEFAULT NULL,
    reset_expires DATETIME DEFAULT NULL
);

-- Categories table
CREATE TABLE categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50) DEFAULT NULL,
    color VARCHAR(7) DEFAULT '#007bff',
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Posts table
CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    user_id INT NOT NULL,
    category_id INT NOT NULL,
    status ENUM(
        'draft',
        'published',
        'hidden'
    ) DEFAULT 'published',
    views INT DEFAULT 0,
    is_pinned BOOLEAN DEFAULT FALSE,
    is_locked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE,
    INDEX idx_category (category_id),
    INDEX idx_user (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_status (status)
);

-- Replies table
CREATE TABLE replies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content TEXT NOT NULL,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    parent_id INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES replies (id) ON DELETE CASCADE,
    INDEX idx_post (post_id),
    INDEX idx_user (user_id),
    INDEX idx_created_at (created_at)
);

-- Likes table
CREATE TABLE likes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    post_id INT DEFAULT NULL,
    reply_id INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
    FOREIGN KEY (reply_id) REFERENCES replies (id) ON DELETE CASCADE,
    UNIQUE KEY unique_post_like (user_id, post_id),
    UNIQUE KEY unique_reply_like (user_id, reply_id)
);

-- Reports table
CREATE TABLE reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    reporter_id INT NOT NULL,
    post_id INT DEFAULT NULL,
    reply_id INT DEFAULT NULL,
    user_id INT DEFAULT NULL,
    reason ENUM(
        'spam',
        'inappropriate',
        'harassment',
        'fake_news',
        'other'
    ) NOT NULL,
    description TEXT,
    status ENUM(
        'pending',
        'reviewed',
        'resolved',
        'dismissed'
    ) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_by INT DEFAULT NULL,
    reviewed_at TIMESTAMP NULL DEFAULT NULL,
    FOREIGN KEY (reporter_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
    FOREIGN KEY (reply_id) REFERENCES replies (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
);

-- Messages table (for private messaging)
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    subject VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_receiver (receiver_id),
    INDEX idx_sender (sender_id)
);

-- Sessions table (for session management)
CREATE TABLE user_sessions (
    id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Notifications table
CREATE TABLE notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM(
        'reply',
        'like',
        'mention',
        'message',
        'system'
    ) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    related_id INT DEFAULT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_user_unread (user_id, is_read)
);

-- Insert sample categories
INSERT INTO
    categories (
        name,
        description,
        icon,
        color
    )
VALUES (
        'Teknologi',
        'Diskusi tentang teknologi terkini',
        'fas fa-laptop',
        '#007bff'
    ),
    (
        'Pendidikan',
        'Topik seputar pendidikan dan pembelajaran',
        'fas fa-graduation-cap',
        '#28a745'
    ),
    (
        'Kesehatan',
        'Informasi dan diskusi tentang kesehatan',
        'fas fa-heartbeat',
        '#dc3545'
    ),
    (
        'Ekonomi',
        'Pembahasan masalah ekonomi dan bisnis',
        'fas fa-chart-line',
        '#ffc107'
    ),
    (
        'Politik',
        'Diskusi politik dan pemerintahan',
        'fas fa-balance-scale',
        '#6f42c1'
    ),
    (
        'Sosial',
        'Isu-isu sosial masyarakat',
        'fas fa-users',
        '#17a2b8'
    ),
    (
        'Budaya',
        'Kebudayaan dan tradisi',
        'fas fa-theater-masks',
        '#fd7e14'
    ),
    (
        'Olahraga',
        'Berita dan diskusi olahraga',
        'fas fa-football-ball',
        '#20c997'
    ),
    (
        'Hiburan',
        'Film, musik, dan hiburan lainnya',
        'fas fa-film',
        '#e83e8c'
    ),
    (
        'Lainnya',
        'Topik umum dan lainnya',
        'fas fa-comments',
        '#6c757d'
    );

-- Insert sample admin user
INSERT INTO
    users (
        username,
        email,
        password,
        full_name,
        role
    )
VALUES (
        'admin',
        'admin@forum.com',
        '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
        'Administrator',
        'admin'
    );

-- Insert sample moderator user
INSERT INTO
    users (
        username,
        email,
        password,
        full_name,
        role
    )
VALUES (
        'moderator',
        'mod@forum.com',
        '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
        'Moderator Forum',
        'moderator'
    );

-- Insert sample regular users
INSERT INTO
    users (
        username,
        email,
        password,
        full_name,
        role
    )
VALUES (
        'john_doe',
        'john@example.com',
        '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
        'John Doe',
        'user'
    ),
    (
        'jane_smith',
        'jane@example.com',
        '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
        'Jane Smith',
        'user'
    ),
    (
        'bob_wilson',
        'bob@example.com',
        '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
        'Bob Wilson',
        'user'
    );

-- Insert sample posts
INSERT INTO
    posts (
        title,
        content,
        user_id,
        category_id
    )
VALUES (
        'Selamat datang di Forum Masyarakat!',
        '<p>Halo semua! Selamat datang di Forum Masyarakat, tempat berdiskusi dan berbagi informasi.</p>
  <p>Mari kita gunakan platform ini untuk:</p>
  <ul>
    <li>Berdiskusi tentang isu-isu penting</li>
    <li>Berbagi pengetahuan dan pengalaman</li>
    <li>Membangun komunikasi yang sehat</li>
  </ul>
  <p>Ayo mulai berdiskusi!</p>',
        1,
        10
    ),
    (
        'Tips Belajar Programming untuk Pemula',
        '<h3>Tips Sukses Belajar Programming</h3>
  <p>Bagi yang baru mulai belajar programming, berikut beberapa tips:</p>
  <ol>
    <li>Mulai dari bahasa yang mudah dipahami</li>
    <li>Praktik setiap hari minimal 1 jam</li>
    <li>Bergabung dengan komunitas programmer</li>
    <li>Jangan takut membuat kesalahan</li>
  </ol>
  <p>Semangat belajar! 💪</p>',
        3,
        1
    ),
    (
        'Pentingnya Pendidikan Karakter di Sekolah',
        '<p>Pendidikan karakter sangat penting untuk membentuk generasi yang berkualitas.</p>
  <p>Beberapa nilai karakter yang perlu ditanamkan:</p>
  <ul>
    <li>Kejujuran</li>
    <li>Tanggung jawab</li>
    <li>Disiplin</li>
    <li>Toleransi</li>
  </ul>',
        4,
        2
    ),
    (
        'Cara Menjaga Kesehatan di Masa Pandemi',
        '<p>Tips menjaga kesehatan:</p>
  <ul>
    <li>Cuci tangan secara teratur</li>
    <li>Gunakan masker saat beraktivitas</li>
    <li>Jaga jarak aman</li>
    <li>Konsumsi makanan bergizi</li>
    <li>Olahraga rutin</li>
  </ul>
  <p>Kesehatan adalah harta yang paling berharga!</p>',
        5,
        3
    );

-- Insert sample replies
INSERT INTO
    replies (content, post_id, user_id)
VALUES (
        'Terima kasih atas sambutannya! Saya senang bisa bergabung di forum ini.',
        1,
        3
    ),
    (
        'Forum yang bagus, semoga bisa menjadi tempat diskusi yang produktif.',
        1,
        4
    ),
    (
        'Tips yang sangat membantu! Saya sedang belajar Python sekarang.',
        2,
        5
    ),
    (
        'Setuju sekali dengan pentingnya pendidikan karakter.',
        3,
        3
    ),
    (
        'Tips kesehatan yang praktis, akan saya coba terapkan.',
        4,
        4
    );

-- Create indexes for better performance
CREATE INDEX idx_posts_search ON posts (title, content);

CREATE INDEX idx_users_username ON users (username);

CREATE INDEX idx_posts_category_date ON posts (category_id, created_at);

-- Create sample vulnerable stored procedure (for SQL injection testing)
DELIMITER / /

CREATE PROCEDURE GetUserPosts(IN user_input VARCHAR(255))
BEGIN
    SET @sql = CONCAT('SELECT * FROM posts WHERE user_id = ', user_input);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END//

DELIMITER;

-- Sample vulnerable view
CREATE VIEW user_post_stats AS
SELECT
    u.id,
    u.username,
    u.full_name,
    COUNT(p.id) as total_posts,
    MAX(p.created_at) as last_post_date
FROM users u
    LEFT JOIN posts p ON u.id = p.user_id
GROUP BY
    u.id,
    u.username,
    u.full_name;

-- Create triggers for potential vulnerabilities
DELIMITER / /

CREATE TRIGGER update_user_activity 
    AFTER INSERT ON posts 
    FOR EACH ROW 
BEGIN
    UPDATE users 
    SET last_activity = NOW() 
    WHERE id = NEW.user_id;
END//

DELIMITER;

DELIMITER / /

CREATE TRIGGER log_user_login 
    AFTER INSERT ON user_sessions 
    FOR EACH ROW 
BEGIN
    INSERT INTO notifications (user_id, type, title, content) 
    VALUES (NEW.user_id, 'system', 'Login Detected', 
            CONCAT('New login from IP: ', NEW.ip_address));
END//

DELIMITER;