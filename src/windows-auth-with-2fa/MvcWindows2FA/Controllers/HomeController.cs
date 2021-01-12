using Google.Authenticator;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MvcWindows2FA.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MvcWindows2FA.Controllers
{
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [Route("TwoFactorChallenge")]
        [AllowAnonymous]
        public IActionResult TwoFactorChallenge()
        {
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            var username = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;
            var userId = User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.PrimarySid)?.Value.Replace(" ", "").Replace("-", "");
            var setupInfo = tfa.GenerateSetupCode("MVC Windows 2FA", username, userId, true);

            string qrCodeImageUrl = setupInfo.QrCodeSetupImageUrl;
            string manualEntrySetupCode = setupInfo.ManualEntryKey;

            return View(new TwoFactorChallengeViewModel { QrCodeImageUrl = qrCodeImageUrl, ManualEntrySetupCode = manualEntrySetupCode });
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
