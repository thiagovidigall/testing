using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using CreateJWT.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace CreateJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        // GET: api/<AuthenticationController>
        [HttpGet]
        public string Get(string user, string pass)
        {
            //return new string[] { "value1", "value2" };
            if (user == "admin")
                return AuthenticationConfig.GenerateJSONWebToken(user);
            else
                return string.Empty;
        }

        // POST api/<AuthenticationController>
        [Authorize]
        [HttpPost]
        public string Post()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IEnumerable<Claim> claim = identity.Claims;
            var userName = claim.Where(c => c.Type == "UserName").Select(c => c.Value).SingleOrDefault();
            return "Welcome to " + userName + "!";
        }
    }
}
