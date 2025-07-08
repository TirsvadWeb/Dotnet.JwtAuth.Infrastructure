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

/// <summary>
/// Provides authentication services for user registration, login, and token management.
/// </summary>
public class AuthService(AuthDbContext ctx, IConfiguration configuration) : IAuthService
{
    /// <inheritdoc />
    public async Task<TokenRepondseDto?> LoginAsync(ApplicationUserDto request)
    {
        ApplicationUser? user = await ctx.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName);

        if (user == null)
        {
            return null;
        }
        if (new PasswordHasher<ApplicationUser>().VerifyHashedPassword(user, user.PasswordHash!, request.Password) == PasswordVerificationResult.Failed)
        {
            return null;
        }

        return await CreateTokenResponseAsync(user);
    }

    /// <inheritdoc />
    public async Task<ApplicationUser?> RegisterAsync(ApplicationUserDto request)
    {
        if (await ctx.Users.AnyAsync(u => u.UserName == request.UserName))
        {
            return null;
        }

        ApplicationUser user = new();

        var hashedPassword = new PasswordHasher<ApplicationUser>()
            .HashPassword(user, request.Password);

        user.UserName = request.UserName;
        user.PasswordHash = hashedPassword;

        ctx.Users.Add(user);
        await ctx.SaveChangesAsync();

        return user;
    }

    /// <inheritdoc />
    public async Task<TokenRepondseDto?> RefreshTokensAsync(RefreshTokenRequestDto request)
    {
        ApplicationUser? user = await ValidateRefreshTokenAsync(request.ApplicationUserId, request.RefreshToken);
        if (user is null)
            return null;

        return await CreateTokenResponseAsync(user);
    }

    /// <summary>
    /// Creates a <see cref="TokenRepondseDto"/> containing a new access token and refresh token for the specified user.
    /// </summary>
    /// <param name="user">The user for whom to create the token response.</param>
    /// <returns>A <see cref="TokenRepondseDto"/> with access and refresh tokens.</returns>
    private async Task<TokenRepondseDto> CreateTokenResponseAsync(ApplicationUser user)
    {
        return new()
        {
            AccessToken = CreateToken(user),
            RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
        };
    }

    /// <summary>
    /// Validates the provided refresh token for the specified user.
    /// </summary>
    /// <param name="userId">The unique identifier of the user.</param>
    /// <param name="refreshToken">The refresh token to validate.</param>
    /// <returns>The <see cref="User"/> if the refresh token is valid; otherwise, <c>null</c>.</returns>
    private async Task<ApplicationUser?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
    {
        ApplicationUser? user = await ctx.Users.FindAsync(userId);
        if (user == null
            || user.RefreshToken != refreshToken
            || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return null;
        }
        return user;
    }

    /// <summary>
    /// Generates a secure random refresh token.
    /// </summary>
    /// <returns>A base64-encoded refresh token string.</returns>
    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
        }
        return Convert.ToBase64String(randomNumber);
    }

    /// <summary>
    /// Generates a new refresh token, saves it to the user, and persists the change.
    /// </summary>
    /// <param name="user">The user for whom to generate and save the refresh token.</param>
    /// <returns>The generated refresh token string.</returns>
    private async Task<string> GenerateAndSaveRefreshTokenAsync(ApplicationUser user)
    {
        string refreshToken = GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // Set expiration for 7 days
        // Assuming you have a RefreshTokens table to store refresh tokens
        await ctx.SaveChangesAsync();
        return refreshToken;
    }

    /// <summary>
    /// Creates a JWT access token for the specified user.
    /// </summary>
    /// <param name="user">The user for whom to create the token.</param>
    /// <returns>A JWT access token string.</returns>
    private string CreateToken(ApplicationUser user)
    {
        List<Claim> claims = [
            new Claim(ClaimTypes.Name, user.UserName !),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        ];

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