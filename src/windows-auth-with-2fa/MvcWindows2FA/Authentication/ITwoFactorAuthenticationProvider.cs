using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MvcWindows2FA.Authentication
{
    public interface ITwoFactorAuthenticationProvider
    {
        Task<bool> HasTwoFactorSetup();
        Task<bool> ValidateTwoFactorPIN(string accountSecret, string validationCode);
        Task<string> GetCurrentAccountSecret();
        Task SaveAuthenticatorSettings(string accountSecret);
        string CurrentUserSID { get; }
        string CurrentUsername { get; }
        Task<QrCodeSetupModel> GenerateSetupCode(string accountName, string accountSecret = null);
    }

    public class QrCodeSetupModel
    {
        public string ManualEntryKey { get; }
        public string FormattedEntrySetupCode { get { return FormatKey(ManualEntryKey); } }
        public string QrCodeImageDataUri { get; }
        public string AccountSecret { get; }

        public QrCodeSetupModel(string manualEntryKey, string qrCodeImageDataUri, string accountSecret)
        {
            ManualEntryKey = manualEntryKey;
            QrCodeImageDataUri = qrCodeImageDataUri;
            AccountSecret = accountSecret;
        }

        private string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }
    }
}
