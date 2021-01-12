using Google.Authenticator;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MvcWindows2FA.Authentication;
using MvcWindows2FA.Data;
using MvcWindows2FA.ViewModels;
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
    [Route("Authentication")]
    public class AuthenticationController : Controller
    {
        private readonly ITwoFactorAuthenticationProvider _twoFactorAuthenticationProvider;

        public AuthenticationController(ITwoFactorAuthenticationProvider twoFactorAuthenticationProvider)
        {
            _twoFactorAuthenticationProvider = twoFactorAuthenticationProvider;
        }

        [Route("SignOut")]
        public async Task<IActionResult> SignOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        [Route("2FA")]
        public async Task<IActionResult> Index(TwoFactorVerifyViewModel vm = null)
        {
            var userId = _twoFactorAuthenticationProvider.CurrentUserSID;
            var hasTwoFactorSetup = await _twoFactorAuthenticationProvider.HasTwoFactorSetup(userId);

            // Check for 2FA setup (redirect if not found)
            if (!hasTwoFactorSetup)
                return RedirectToAction("Setup", "Authentication");

            // Check if validation code is posted
            if (vm.ValidationCode == null)
            {
                // Prompt for validation code
                var accountSecrect = await _twoFactorAuthenticationProvider.GetCurrentAccountSecret(userId);
                return View(new TwoFactorVerifyViewModel { ValidationCode = null, Token = accountSecrect });
            }
            else
            {
                // Verify validation code
                var accountSecrect = await _twoFactorAuthenticationProvider.GetCurrentAccountSecret(userId);
                if (await _twoFactorAuthenticationProvider.ValidateTwoFactorPIN(accountSecrect, vm.ValidationCode))
                {
                    var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.NameIdentifier, userId),
                            new Claim(ClaimTypes.PrimarySid, userId),
                            new Claim(ClaimTypes.Name, GetUserDisplayName)
                        };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var cliamsPrincipal = new ClaimsPrincipal(claimsIdentity);

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                                  cliamsPrincipal,
                                                  new AuthenticationProperties { IsPersistent = false });

                    return Ok();
                }

                return BadRequest("Validation of pin failed!");
            }
        }

        [Route("Setup")]
        public async Task<IActionResult> Setup(TwoFactorChallengeViewModel vm = null)
        {
            var username = _twoFactorAuthenticationProvider.CurrentUsername;
            var userId = _twoFactorAuthenticationProvider.CurrentUserSID;
            var hasTwoFactorSetup = await _twoFactorAuthenticationProvider.HasTwoFactorSetup(userId);

            // If has 2FA setup, redirect to validation
            if (hasTwoFactorSetup)
                return RedirectToAction("Index", "Authentication");

            // Check if validation code is posted
            if (vm.ValidationCode == null)
            {
                var setupInfo = await _twoFactorAuthenticationProvider.GenerateSetupCode(username);
                return View(new TwoFactorChallengeViewModel
                {
                    QrCodeImageUrl = setupInfo.QrCodeImageDataUri,
                    FormattedEntrySetupCode = setupInfo.FormattedEntrySetupCode,
                    Token = setupInfo.AccountSecret
                });
            }


            // If NOT found create 2FA setup and signin
            if (await _twoFactorAuthenticationProvider.ValidateTwoFactorPIN(vm.Token, vm.ValidationCode))
            {
                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, userId),
                        new Claim(ClaimTypes.PrimarySid, userId),
                        new Claim(ClaimTypes.Name, GetUserDisplayName)
                    };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var cliamsPrincipal = new ClaimsPrincipal(claimsIdentity);

                await _twoFactorAuthenticationProvider.SaveAuthenticatorSettings(vm.Token, userId);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                              cliamsPrincipal,
                                              new AuthenticationProperties { IsPersistent = false });

                return Ok();
            }

            return BadRequest("Verifictation code validation failed!");
        }

        private string GetUserDisplayName =>
            User.Identity.Name ?? WindowsIdentity.GetCurrent().Name;
    }
}
