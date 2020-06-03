using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Internal;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;

namespace CreateJWT2.Controllers
{


    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        [HttpPost("token")]
        public IActionResult Token()
        {

            //2ª Aba, Headers
            var header = Request.Headers["Authorization"];
            if (header.ToString().StartsWith("Basic"))
            {


                var credValue = header.ToString().Substring("Basic ".Length).Trim();
                var userNameAndPassec = Encoding.UTF8.GetString(Convert.FromBase64String(credValue));//admin:pass
                var userNameAndPass = userNameAndPassec.Split(":");

                if (userNameAndPass[0] == "Admin" && userNameAndPass[1] == "pass")              {


                    //1ª Aba, apenas os Params + Authorization
                    var claimData = new[] { new Claim(ClaimTypes.Name, "username") };
                    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("D76F1904209193A5C6234195E995E90CD85CD2235B06C1E237FA94FCCD2D852A"));
                    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

                    var token = new JwtSecurityToken(
                        issuer: "mysite.com",
                        audience: "mysite.com",
                        expires: DateTime.Now.AddMinutes(10),
                        claims: claimData,
                        signingCredentials: credentials
                        );

                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                    return Ok(tokenString);
                }
            }
            return BadRequest("wrong request");
        }

        
    }
}
