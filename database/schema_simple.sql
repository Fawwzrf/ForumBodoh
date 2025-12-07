-- Simple schema without complex stored procedures
CREATE DATABASE IF NOT EXISTS forum_masyarakat;

USE forum_masyarakat;

-- Users table
CREATE TABLE IF NOT EXISTS users (
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
CREATE TABLE IF NOT EXISTS categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50) DEFAULT NULL,
    color VARCHAR(7) DEFAULT '#007bff',
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Posts table
CREATE TABLE IF NOT EXISTS posts (
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
    INDEX idx_posts_user (user_id),
    INDEX idx_posts_category (category_id),
    INDEX idx_posts_status (status),
    INDEX idx_posts_created (created_at)
);

-- Replies table
CREATE TABLE IF NOT EXISTS replies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    is_hidden BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_replies_post (post_id),
    INDEX idx_replies_user (user_id),
    INDEX idx_replies_created (created_at)
);

-- Votes table
CREATE TABLE IF NOT EXISTS votes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    post_id INT DEFAULT NULL,
    reply_id INT DEFAULT NULL,
    vote_type ENUM('up', 'down') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
    FOREIGN KEY (reply_id) REFERENCES replies (id) ON DELETE CASCADE,
    UNIQUE KEY unique_post_vote (user_id, post_id),
    UNIQUE KEY unique_reply_vote (user_id, reply_id)
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
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

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
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

-- Sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type ENUM(
        'message',
        'reply',
        'mention',
        'system'
    ) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_user_notifications (user_id, is_read)
);

-- Insert default admin user (password: password)
INSERT IGNORE INTO
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
INSERT IGNORE INTO
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
INSERT IGNORE INTO
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

-- Insert sample categories
INSERT IGNORE INTO
    categories (
        id,
        name,
        description,
        icon,
        color
    )
VALUES (
        1,
        'General Discussion',
        'General topics and discussions',
        'fas fa-comments',
        '#007bff'
    ),
    (
        2,
        'Technology',
        'Tech news and discussions',
        'fas fa-laptop',
        '#28a745'
    ),
    (
        3,
        'Security',
        'Security topics and vulnerabilities',
        'fas fa-shield-alt',
        '#dc3545'
    ),
    (
        4,
        'Programming',
        'Programming languages and development',
        'fas fa-code',
        '#ffc107'
    );

-- Insert sample posts with intentional vulnerabilities for testing
INSERT IGNORE INTO
    posts (
        id,
        title,
        content,
        user_id,
        category_id
    )
VALUES (
        1,
        'Welcome to the Forum!',
        'This is a sample post with <script>alert("XSS")</script> content for testing purposes.',
        1,
        1
    ),
    (
        2,
        'Security Discussion',
        'Let\'s discuss web security. What are your thoughts on <img src="x" onerror="alert(\'XSS\')">',
        2,
        3
    ),
    (
        3,
        'Programming Tips',
        'Share your best programming tips here! <svg onload=alert("SVG XSS")>',
        3,
        4
    );

-- Insert sample replies
INSERT IGNORE INTO
    replies (post_id, user_id, content)
VALUES (
        1,
        2,
        'Great forum! Looking forward to discussions with <script>console.log("XSS in reply")</script>'
    ),
    (
        1,
        3,
        'Thanks for setting this up! <img src=x onerror=alert("Reply XSS")>'
    ),
    (
        2,
        1,
        'Security is very important in web development <iframe src="javascript:alert(\'iframe XSS\')">'
    );