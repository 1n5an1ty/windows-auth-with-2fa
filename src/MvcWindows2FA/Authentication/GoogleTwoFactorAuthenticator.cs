using Google.Authenticator;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MvcWindows2FA.Authentication.Models;
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
        private readonly TwoFactorAuthenticationProviderOptions _options;
        private readonly TwoFactorAuthenticator _twoFactorAuthenticator;
        private readonly ApplicationDbContext _dbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly string _currentUserSID;
        private readonly string _currentUsername;

        public GoogleTwoFactorAuthenticator(IOptionsMonitor<TwoFactorAuthenticationProviderOptions> options,
                                            TwoFactorAuthenticator twoFactorAuthenticator,
                                            ApplicationDbContext dbContext,
                                            IHttpContextAccessor httpContextAccessor)
        {
            _options = options.CurrentValue;
            _twoFactorAuthenticator = twoFactorAuthenticator;
            _dbContext = dbContext;
            _httpContextAccessor = httpContextAccessor;
            _currentUserSID = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.PrimarySid)?.Value;
            _currentUsername = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
        }

        public Task<QrCodeSetupModel> GenerateSetupCode(string accountName, string accountSecret = null)
        {
            var userToken = accountSecret ?? Guid.NewGuid().ToString("N");
            var setupInfo = _twoFactorAuthenticator.GenerateSetupCode(_options.ApplicationName, accountName, userToken, false);

            return Task.FromResult(new QrCodeSetupModel(setupInfo.ManualEntryKey, setupInfo.QrCodeSetupImageUrl, userToken));
        }

        public string CurrentUserSID { get { return _currentUserSID; } }
        public string CurrentUsername { get { return _currentUsername; } }

        public Task SaveAuthenticatorSettings(string accountSecret, string userId)
        {
            _dbContext.UserTokens.Add(new Data.Models.User2FactorAuths { UserId = userId, Name = _options.TokenName, Value = accountSecret });
            return _dbContext.SaveChangesAsync();
        }

        public Task<bool> HasTwoFactorSetup(string userId) =>
            _dbContext.UserTokens.AnyAsync(x => x.UserId == userId && x.Name == _options.TokenName);

        public Task<string> GetCurrentAccountSecret(string userId) =>
            _dbContext.UserTokens.Where(x => x.UserId == userId && x.Name == _options.TokenName).Select(x => x.Value).FirstOrDefaultAsync();

        public Task<bool> ValidateTwoFactorPIN(string accountSecret, string validationCode) =>
            Task.FromResult(_twoFactorAuthenticator.ValidateTwoFactorPIN(accountSecret, validationCode));
    }
}
