using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcWindows2FA.ViewModels
{
    public class TwoFactorVerifyViewModel
    {
        public string ValidationCode { get; set; }
        public string Token { get; set; }
    }
}
