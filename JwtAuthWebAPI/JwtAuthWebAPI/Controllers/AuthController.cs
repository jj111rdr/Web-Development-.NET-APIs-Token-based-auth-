using JwtAuthWebAPI.Enitites;
using JwtAuthWebAPI.Enitites.Models;
using JwtAuthWebAPI.Enitites.Models.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
            {
                return BadRequest("Username already exists.");
            }
            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
            if (token is null)
            {
                return BadRequest("Invalid username or password.");
            }
            return Ok(token);
        }
        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var token = await authService.RefreshTokenAsync(request);
            if (token is null || token.AccessToken is null || token.RefreshToken is null)
            {
                return BadRequest("Invalid refresh token.");
            }
            return Ok(token);
        }
        [Authorize]
        [HttpGet("authenticated")]
        public IActionResult AuthenticatedOnlyEndpoint()
        {
            return Ok("You are authenticated and can access this endpoint.");
        }
        [Authorize(Roles ="Admin")]
        [HttpGet("admin")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("You are an admin.");
        }
    }
}
