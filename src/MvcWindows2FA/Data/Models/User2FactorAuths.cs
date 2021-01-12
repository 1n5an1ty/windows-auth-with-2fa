using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MvcWindows2FA.Data.Models
{
    public class User2FactorAuths
    {
        [Required]
        [StringLength(450)]
        public string UserId { get; set; }
        [Required]
        [StringLength(450)]
        public string Name { get; set; }
        public string Value { get; set; }
    }
}
