using Google.Authenticator;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using MvcWindows2FA.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MvcWindows2FA.Authentication
{
    public class GoogleTwoFactorAuthenticator : ITwoFactorAuthenticationProvider
    {
        private readonly TwoFactorAuthenticator _twoFactorAuthenticator;
        private readonly ApplicationDbContext _dbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly string _currentUserSID;
        private readonly string _currentUsername;

        public GoogleTwoFactorAuthenticator(TwoFactorAuthenticator twoFactorAuthenticator, ApplicationDbContext dbContext, IHttpContextAccessor httpContextAccessor)
        {
            _twoFactorAuthenticator = twoFactorAuthenticator;
            _dbContext = dbContext;
            _httpContextAccessor = httpContextAccessor;
            _currentUserSID = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.PrimarySid)?.Value;
            _currentUsername = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
        }

        public Task<QrCodeSetupModel> GenerateSetupCode(string accountName, string accountSecret = null)
        {
            var userToken = accountSecret ?? Guid.NewGuid().ToString("N");
            var setupInfo = _twoFactorAuthenticator.GenerateSetupCode("MVC Win2FA", accountName, userToken, false);

            return Task.FromResult(new QrCodeSetupModel(setupInfo.ManualEntryKey, setupInfo.QrCodeSetupImageUrl, userToken));
        }

        public string CurrentUserSID { get { return _currentUserSID; } }
        public string CurrentUsername { get { return _currentUsername; } }

        public Task SaveAuthenticatorSettings(string accountSecret)
        {
            _dbContext.UserTokens.Add(new Data.Models.User2FactorAuths { UserId = _currentUserSID, Name = "AuthenticatorKey", Value = accountSecret });
            return _dbContext.SaveChangesAsync();
        }

        public Task<bool> HasTwoFactorSetup() =>
            _dbContext.UserTokens.AnyAsync(x => x.UserId == _currentUserSID && x.Name == "AuthenticatorKey");

        public Task<string> GetCurrentAccountSecret() =>
            _dbContext.UserTokens.Where(x => x.UserId == _currentUserSID && x.Name == "AuthenticatorKey").Select(x => x.Value).FirstOrDefaultAsync();

        public Task<bool> ValidateTwoFactorPIN(string accountSecret, string validationCode) =>
            Task.FromResult(_twoFactorAuthenticator.ValidateTwoFactorPIN(accountSecret, validationCode));
    }
}
