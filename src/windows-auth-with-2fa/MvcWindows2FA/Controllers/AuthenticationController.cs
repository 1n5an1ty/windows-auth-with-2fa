using Google.Authenticator;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MvcWindows2FA.Data;
using MvcWindows2FA.Models;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace MvcWindows2FA.Controllers
{
    [Authorize(AuthenticationSchemes = NegotiateDefaults.AuthenticationScheme)]
    public class AuthenticationController : Controller
    {
        private readonly TwoFactorAuthenticator _twoFactorAuthenticator;
        private readonly ApplicationDbContext _dbContext;

        public AuthenticationController(TwoFactorAuthenticator twoFactorAuthenticator, ApplicationDbContext dbContext)
        {
            _twoFactorAuthenticator = twoFactorAuthenticator;
            _dbContext = dbContext;
        }

        [Route("Authentication/SignOut")]
        public async Task<IActionResult> SignOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        [Route("Authentication/2FA")]
        public async Task<IActionResult> Index(TwoFactorChallengeViewModel vm = null)
        {
            var username = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            var userId = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.PrimarySid)?.Value;


            var existingRec = await _dbContext.UserTokens.FindAsync(userId, "AuthenticatorKey");

            if (vm?.ValidationCode == null && existingRec == null)
            {
                var userToken = Guid.NewGuid().ToString("N");
                var setupInfo = _twoFactorAuthenticator.GenerateSetupCode("MVC Win2FA", username, userToken, false);

                string qrCodeImageUrl = setupInfo.QrCodeSetupImageUrl;
                string manualEntrySetupCode = setupInfo.ManualEntryKey;

                return View(new TwoFactorChallengeViewModel { QrCodeImageUrl = qrCodeImageUrl, FormattedEntrySetupCode = FormatKey(manualEntrySetupCode), Token = userToken });
            }

            if (vm?.ValidationCode == null && existingRec != null)
            {
                return View(new TwoFactorChallengeViewModel { QrCodeImageUrl = null, FormattedEntrySetupCode = null, Token = existingRec.Value });
            }

            else if (vm?.ValidationCode != null && existingRec != null)
            {
                var isCorrectPIN = _twoFactorAuthenticator.ValidateTwoFactorPIN(existingRec.Value, vm.ValidationCode);
                if (isCorrectPIN)
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, userId),
                        new Claim(ClaimTypes.Name, GetUserDisplayName)
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var cliamsPrincipal = new ClaimsPrincipal(claimsIdentity);

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                                  cliamsPrincipal,
                                                  new AuthenticationProperties { IsPersistent = false });

                    return Ok();
                }
            }
            else if (vm?.ValidationCode != null && existingRec == null && vm.Token != null)
            {
                var isCorrectPIN = _twoFactorAuthenticator.ValidateTwoFactorPIN(vm.Token, vm.ValidationCode);
                if (isCorrectPIN)
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, userId),
                        new Claim(ClaimTypes.Name, GetUserDisplayName)
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var cliamsPrincipal = new ClaimsPrincipal(claimsIdentity);

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                                  cliamsPrincipal,
                                                  new AuthenticationProperties { IsPersistent = false });

                    _dbContext.UserTokens.Add(new Data.Models.User2FactorAuths { UserId = userId, Name = "AuthenticatorKey", Value = vm.Token });
                    await _dbContext.SaveChangesAsync();

                    return Ok();
                }
            }

            return BadRequest();
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

        public string GetUserDisplayName =>
            User.Identity.Name ?? WindowsIdentity.GetCurrent().Name;
    }
}
