using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MvcWindows2FA.Tokens
{
    public class IdTokenGenerator
    {
        private readonly string _characters = "ABCDEFGHIJKLMNPQRSTUVWXYZ";
        private readonly int _size;

        public IdTokenGenerator()
        {
            _size = 32;
        }

        public string GenerateIdToken()
        {
            var sb = new StringBuilder();
            var length = _size;

            while (length-- != 0)
            {
                var charIndex = new Random().Next(0, _characters.Length);
                sb.Append(_characters[charIndex]);
            }

            return sb.ToString();
        }
    }
}
