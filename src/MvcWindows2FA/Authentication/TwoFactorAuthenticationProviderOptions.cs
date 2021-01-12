using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcWindows2FA.Authentication
{
    public class TwoFactorAuthenticationProviderOptions
    {
        public string ApplicationName { get; set; }
        public string TokenName { get; set; }
    }
}
