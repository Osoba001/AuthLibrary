using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Models
{
    public class AuthConfigModel
    {
        public string ConnString { get; set; }
        public string SecretKey { get; set; }
        public int AccessTokenExpireTimeInMins { get; set; }
        public int RefreshTokenExpireTimeInMins { get; set;}
        
    }
}
