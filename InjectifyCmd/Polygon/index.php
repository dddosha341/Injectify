<?php
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Уязвимое приложение для демонстрации SQL-инъекций</title>
</head>
<body>
    <h1>Поиск пользователя</h1>
    <form action="search.php" method="GET">
        <label for="id">ID пользователя:</label>
        <input type="text" name="id" id="id">
        <br><br>
        <label for="name">Имя пользователя:</label>
        <input type="text" name="name" id="name">
        <br><br>
        <input type="submit" value="Поиск">
    </form>
</body>
</html>