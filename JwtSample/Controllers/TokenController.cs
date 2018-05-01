using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JwtSample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JwtSample.Controllers
{
    [Produces("application/json")]
    [Route("api/Token")]
    public class TokenController : Controller
    {
        private readonly IConfiguration _configuration;

        public TokenController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult GetToken([FromBody] UserAuth user)
        {
            if (user.UserName != "Otavio" || user.UserPassword != "SenhaPadrao") return BadRequest("Unsafe data: Poor cryptography. Please use a MD5 Hash for user and password.");

            var symmetricKey = Convert.FromBase64String(_configuration["SecurityKey"]);
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.UserPassword)
                }),
                Audience = _configuration["Audience"],
                Issuer = _configuration["Issuer"],
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(tokenHandler.WriteToken(stoken));
        }
    }
}