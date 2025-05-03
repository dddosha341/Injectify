using System.Net.Http;
using System.Text;
using System.Web;

namespace Injectify.Core
{
    public abstract class InjectifyScanner : IScanner
    {
        public string TargetUrl { get; set; }
        public HttpClient HttpClient { get; set; }

        protected InjectifyScanner(string targetUrl)
        {
            TargetUrl = targetUrl;
            HttpClient = new HttpClient();
        }

        public abstract Task<bool> IsVulnerableAsync();

        public static string AddPayloadToUrl(string url, string payload)
        {
            if (url.Contains("="))
                return url + Uri.EscapeDataString(payload);

            return url;
        }

        /// <summary>
        /// 
        /// Универсальный метод для отправки запросов.
        ///  Пример запроса с GET:
        /// SendRequestAsync("GET", "https://site.com/page.php?id=1")
        /// 
        /// Пример запроса с POST:
        /// SendRequestAsync("POST", "https://site.com/login", new Dictionary<string, string>
        /// {
        ///     { "username", "admin'" },
        ///     { "password", "pass" }
        /// })
        /// </summary>
        public virtual async Task<string> SendRequestAsync(string method, string url, Dictionary<string, string>? postData = null)
        {
            HttpResponseMessage response;

            if (method.ToUpper() == "POST" && postData != null)
            {
                var content = new FormUrlEncodedContent(postData);
                response = await HttpClient.PostAsync(url, content);
            }
            else
            {
                response = await HttpClient.GetAsync(url);
            }

            return await response.Content.ReadAsStringAsync();
        }

        public virtual async Task<bool> TestParametersAsync(List<string> payloads, Func<string, string, string, Task<bool>> testFunc)
        {
            var uri = new Uri(TargetUrl);
            var query = HttpUtility.ParseQueryString(uri.Query);
            if (query.Count == 0)
            {
                Log("[-] Нет параметров для тестирования.");
                return false;
            }

            string baseUrl = $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}";

            foreach (var key in query.AllKeys)
            {
                string? originalValue = query[key];
                if (originalValue == null) continue;

                foreach (var payload in payloads)
                {
                    var modifiedQuery = HttpUtility.ParseQueryString(query.ToString());
                    modifiedQuery[key] = originalValue + payload;

                    string modifiedUrl = $"{baseUrl}?{modifiedQuery}";
                    bool result = await testFunc(modifiedUrl, key, payload);
                    if (result) return true;
                }
            }

            return false;
        }

        public virtual void Log(string message)
        {
            Console.WriteLine($"[Injectify] {DateTime.Now:HH:mm:ss} - {message}");
        }
    }
}
