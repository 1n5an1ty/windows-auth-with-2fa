using Google.Authenticator;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MvcWindows2FA.Authentication;
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
        private readonly ITwoFactorAuthenticationProvider _twoFactorAuthenticationProvider;

        public AuthenticationController(ITwoFactorAuthenticationProvider twoFactorAuthenticationProvider)
        {
            _twoFactorAuthenticationProvider = twoFactorAuthenticationProvider;
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
            var username = _twoFactorAuthenticationProvider.CurrentUsername;
            var userId = _twoFactorAuthenticationProvider.CurrentUserSID;
            var hasTwoFactorSetup = await _twoFactorAuthenticationProvider.HasTwoFactorSetup();

            // Check if validation code is posted
            if (vm.ValidationCode == null)
            {
                // Check for existing 2FA setup
                if (!hasTwoFactorSetup)
                {
                    var setupInfo = await _twoFactorAuthenticationProvider.GenerateSetupCode(username);
                    return View(new TwoFactorChallengeViewModel { 
                        QrCodeImageUrl = setupInfo.QrCodeImageDataUri, 
                        FormattedEntrySetupCode = setupInfo.FormattedEntrySetupCode, 
                        Token = setupInfo.AccountSecret 
                    });
                }

                var accountSecrect = await _twoFactorAuthenticationProvider.GetCurrentAccountSecret();
                return View(new TwoFactorChallengeViewModel { QrCodeImageUrl = null, FormattedEntrySetupCode = null, Token = accountSecrect });
            }
            else
            {
                // Check for existing 2FA setup (if found just signin)
                if (hasTwoFactorSetup)
                {
                    var accountSecrect = await _twoFactorAuthenticationProvider.GetCurrentAccountSecret();
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

                    await _twoFactorAuthenticationProvider.SaveAuthenticatorSettings(vm.Token);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                                  cliamsPrincipal,
                                                  new AuthenticationProperties { IsPersistent = false });

                    return Ok();
                }
            }

            // Something went wrong!
            return BadRequest("Validation of pin failed!");
        }

        private string GetUserDisplayName =>
            User.Identity.Name ?? WindowsIdentity.GetCurrent().Name;
    }
}
