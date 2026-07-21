
using Azure.Core;
using JwtAuthWebAPI.Enitites.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthWebAPI.Enitites.Models.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
    {
        public async Task<TokenResponseDto?> LoginAsync(UserDto userDto)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == userDto.Username);
            if (user is null)
            {
                return null;
            }
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, userDto.Password) == PasswordVerificationResult.Failed)
            {
                return null;
            }
            TokenResponseDto tokenResponse = await CreateTokenResponse(user);
            return tokenResponse;
        }

        private async Task<TokenResponseDto> CreateTokenResponse(User? user)
        {
            return new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshToken(user)
            };
        }

        public async Task<User?> RegisterAsync(UserDto userDto)
        {
            if (await context.Users.AnyAsync(u => u.Username == userDto.Username))
            {
                return null;
            }
            var user = new User();
            var hashPassword = new PasswordHasher<User>().HashPassword(user, userDto.Password);

            user.Username = userDto.Username;
            user.PasswordHash = hashPassword;

            context.Users.Add(user);
            await context.SaveChangesAsync();

            return user;
        }

        string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                configuration.GetValue<string>("AppSettings:Token")!));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
        string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
        async Task<string> GenerateAndSaveRefreshToken(User user)
        {
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpireTime = DateTime.UtcNow.AddDays(7);
            context.Users.Update(user);
            await context.SaveChangesAsync();
            return refreshToken;
        }
        async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
        {
            var user = await context.Users.FindAsync(userId);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpireTime < DateTime.UtcNow)
            {
                return null;
            }
            return user;
        }

        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto refreshTokenRequestDto)
        {
            var user = await ValidateRefreshTokenAsync(refreshTokenRequestDto.UserId, refreshTokenRequestDto.RefreshToken);
            if(user is null)
            {
                return null;
            }
            return await CreateTokenResponse(user);
        }
    }
}
