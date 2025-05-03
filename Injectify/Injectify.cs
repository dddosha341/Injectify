using Injectify.Modules;
using Injectify.Core;

namespace Injectify
{
    public class Injectify
    {
        private readonly string _targetUrl;
        private readonly List<IScanner> _scanners;

        public Injectify(string targetUrl)
        {
            _targetUrl = targetUrl;
            _scanners = new List<IScanner>
            {
                new ErrorBasedScanner(_targetUrl),
                new UnionBasedScanner(_targetUrl),
                new BlindScanner(_targetUrl)
            };
        }

        public async Task<List<string>> ScanAllAsync()
        {
            var foundIssues = new List<string>();

            Console.WriteLine($"[Injectify] 🚀 Начинаем сканирование: {_targetUrl}\n");

            foreach (var scanner in _scanners)
            {
                var scannerName = scanner.GetType().Name;
                Console.WriteLine($"[Injectify] 🔍 Запуск: {scannerName}");

                try
                {
                    bool vulnerable = await scanner.IsVulnerableAsync();

                    if (vulnerable)
                    {
                        string message = $"[!] Уязвимость найдена модулем {scannerName}";
                        Console.WriteLine(message);
                        foundIssues.Add(message);
                    }
                    else
                    {
                        Console.WriteLine($"[+] {scannerName} не нашёл уязвимостей.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Ошибка в модуле {scannerName}: {ex.Message}");
                }

                Console.WriteLine(new string('-', 60));
            }

            if (foundIssues.Count == 0)
            {
                Console.WriteLine("[Injectify] ✅ Уязвимости не найдены.");
            }
            else
            {
                Console.WriteLine($"[Injectify] ⚠️ Обнаружено {foundIssues.Count} уязвимостей.");
            }

            return foundIssues;
        }
    }
}
