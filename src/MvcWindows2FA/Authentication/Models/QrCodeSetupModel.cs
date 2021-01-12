using System.Text;

namespace MvcWindows2FA.Authentication.Models
{
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
