using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CreateJWT.Shared
{
    public static class AuthenticationConfig
    {
        public static string GenerateJSONWebToken(string user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("D76F1904209193A5C6234195E995E90CD85CD2235B06C1E237FA94FCCD2D852A"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim("UserName", user),
                new Claim("Role", "1"),
            };

            IdentityModelEventSource.ShowPII = true;

            var token = new JwtSecurityToken("http://localhost:51139",
                "http://localhost:51139",
                claims,
                DateTime.Now,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        //ConfigureJwtAuthetication

        internal static TokenValidationParameters tokenValidationParams;

        public static void ConfigureJwtAuthetication(this IServiceCollection services)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("D76F1904209193A5C6234195E995E90CD85CD2235B06C1E237FA94FCCD2D852A"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            tokenValidationParams = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                ValidIssuer = "http://localhost:51139",
                ValidateLifetime = true,
                ValidAudience = "http://localhost:51139",
                RequireSignedTokens = true,
                //user our signing credentials key here
                //optionally we can inject an RSA key as
                //IssuerSigningKey = new RsaSecurityKey(rsaParams),
                IssuerSigningKey = credentials.Key,
                ClockSkew = TimeSpan.FromMinutes(30)
            };

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })

            .AddJwtBearer(options =>
             {
                 options.TokenValidationParameters = tokenValidationParams;
#if PROD || UAT
                    options.IncludeErrorDetails = false;
#elif DEBUG
                 options.RequireHttpsMetadata = false;
#endif
             });
        }
    }
}
