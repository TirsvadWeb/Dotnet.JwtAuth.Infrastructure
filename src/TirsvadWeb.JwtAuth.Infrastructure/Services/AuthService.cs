using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using TirsvadWeb.JwtAuth.Application.Dtos;
using TirsvadWeb.JwtAuth.Application.Services;
using TirsvadWeb.JwtAuth.Domain.Entities;
using TirsvadWeb.JwtAuth.Infrastructure.Data;

namespace TirsvadWeb.JwtAuth.Infrastructure.Services;

public class AuthService(AuthDbContext ctx, IConfiguration configuration) : IAuthService
{
    public async Task<TokenRepondseDto?> LoginAsync(UserDto request)
    {
        User? user = await ctx.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName);

        if (user == null)
        {
            return null;
        }
        if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash!, request.Password) == PasswordVerificationResult.Failed)
        {
            return null;
        }

        return await CreateTokenResponseAsync(user);
    }

    public async Task<User?> RegisterAsync(UserDto request)
    {
        if (await ctx.Users.AnyAsync(u => u.UserName == request.UserName))
        {
            return null;
        }

        User user = new();

        var hashedPassword = new PasswordHasher<User>()
            .HashPassword(user, request.Password);

        user.UserName = request.UserName;
        user.PasswordHash = hashedPassword;

        ctx.Users.Add(user);
        await ctx.SaveChangesAsync();

        return user;
    }

    public async Task<TokenRepondseDto?> RefreshTokensAsync(RefreshTokenRequestDto request)
    {
        User? user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
        if (user is null)
            return null;

        return await CreateTokenResponseAsync(user);
    }

    private async Task<TokenRepondseDto> CreateTokenResponseAsync(User user)
    {
        return new()
        {
            AccessToken = CreateToken(user),
            RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
        };
    }

    private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
    {
        User? user = await ctx.Users.FindAsync(userId);
        if (user == null
            || user.RefreshToken != refreshToken
            || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return null;
        }
        return user;
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
        }
        return Convert.ToBase64String(randomNumber);
    }

    private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
    {
        string refreshToken = GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // Set expiration for 7 days
        // Assuming you have a RefreshTokens table to store refresh tokens
        await ctx.SaveChangesAsync();
        return refreshToken;
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = [
            new Claim(ClaimTypes.Name, user.UserName !),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        ];

        // Replace the problematic line in the CreateToken method with the following:
        SymmetricSecurityKey key = new(
            System.Text.Encoding.UTF8.GetBytes(configuration["Jwt:Token"]!)
        );

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

        var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration["Jwt:Issuer"]!,
            audience: configuration["Jwt:Audience"]!,
            claims: claims,
            expires: DateTime.UtcNow.AddDays(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

    }


}
