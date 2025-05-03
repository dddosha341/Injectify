using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Injectify.Core
{
    public interface IScanner
    {
        Task<bool> IsVulnerableAsync();
        void Log(string message);
    }
}
