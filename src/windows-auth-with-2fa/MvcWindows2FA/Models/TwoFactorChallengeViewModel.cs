using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcWindows2FA.Models
{
    public class TwoFactorChallengeViewModel
    {
        public string QrCodeImageUrl { get; set; }
        public string ManualEntrySetupCode { get; set; }
    }
}
