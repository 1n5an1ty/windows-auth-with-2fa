using MvcWindows2FA.Authentication.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcWindows2FA.Authentication
{
    public interface ITwoFactorAuthenticationProvider
    {
        Task<bool> HasTwoFactorSetup(string userId);
        Task<bool> ValidateTwoFactorPIN(string accountSecret, string validationCode);
        Task<string> GetCurrentAccountSecret(string userId);
        Task SaveAuthenticatorSettings(string accountSecre, string userId);
        string CurrentUserSID { get; }
        string CurrentUsername { get; }
        Task<QrCodeSetupModel> GenerateSetupCode(string accountName, string accountSecret = null);
    }
}
