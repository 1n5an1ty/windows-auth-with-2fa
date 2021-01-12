using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcWindows2FA.Models
{
    public class TwoFactorChallengeViewModel
    {
        public string ValidationCode { get; set; }
        public string Token { get; set; }
        public string QrCodeImageUrl { get; set; }
        public string FormattedEntrySetupCode { get; set; }
    }
}
