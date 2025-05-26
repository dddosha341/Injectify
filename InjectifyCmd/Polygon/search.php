<?php
require_once 'config.php';

$id = isset($_GET['id']) ? $_GET['id'] : '';
$name = isset($_GET['name']) ? $_GET['name'] : '';

echo "<h1>Результаты поиска</h1>";

if ($id !== '') {

    $query = "SELECT id, username, email, is_admin FROM users WHERE id = $id";
    try {
        $result = $pdo->query($query);
        echo "<h2>Результаты по ID (Union):</h2>";
        if ($result->rowCount() > 0) {
            while ($row = $result->fetch(PDO::FETCH_ASSOC)) {
                echo "ID: " . htmlspecialchars($row['id']) . ", Username: " . htmlspecialchars($row['username']) . ", Email: " . htmlspecialchars($row['email']) . ", Admin: " . ($row['is_admin'] ? 'Yes' : 'No') . "<br>";
            }
        } else {
            echo "Нет результатов по ID.<br>";
        }
    } catch (PDOException $e) {
        echo "<h2>Error-based инъекция (ID):</h2>";
        echo "Ошибка запроса: " . htmlspecialchars($e->getMessage()) . "<br>";
    }
}


if ($name !== '') {
    $query = "SELECT id, username, email, is_admin FROM users WHERE username = '$name'";
    try {
        $result = $pdo->query($query);
        echo "<h2>Результаты по имени:</h2>";
        if ($result->rowCount() > 0) {
            while ($row = $result->fetch(PDO::FETCH_ASSOC)) {
                echo "ID: " . htmlspecialchars($row['id']) . ", Username: " . htmlspecialchars($row['username']) . ", Email: " . htmlspecialchars($row['email']) . ", Admin: " . ($row['is_admin'] ? 'Yes' : 'No') . "<br>";
            }
        } else {
            echo "Пользователь с именем '" . htmlspecialchars($name) . "' не найден.<br>";
        }
    } catch (PDOException $e) {
        echo "<h2>Blind/Time-based/Union инъекция (Name):</h2>";
        echo "Ошибка запроса: " . htmlspecialchars($e->getMessage()) . "<br>";
    }
}

echo '<br><a href="index.php">Вернуться к поиску</a>';
?>