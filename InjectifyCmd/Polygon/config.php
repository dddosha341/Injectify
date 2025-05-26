<?php
$host = getenv('MYSQL_HOST') ?: 'mysql';
$dbname = getenv('MYSQL_DATABASE') ?: 'vulnerable_app';
$username = getenv('MYSQL_USER') ?: 'root';
$password = getenv('MYSQL_PASSWORD') ?: 'rootpassword';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Ошибка подключения: " . $e->getMessage());
}

$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE
)";
$pdo->exec($sql);

$sql = "INSERT IGNORE INTO users (username, email, is_admin) VALUES
    ('admin', 'admin@example.com', TRUE),
    ('user1', 'user1@example.com', FALSE),
    ('user2', 'user2@example.com', FALSE)";
$pdo->exec($sql);
?>