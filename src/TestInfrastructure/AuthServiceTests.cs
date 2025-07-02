using Microsoft.EntityFrameworkCore;
using Moq;
using TirsvadWeb.JwtAuth.Application.Dtos;
using TirsvadWeb.JwtAuth.Infrastructure.Data;
using TirsvadWeb.JwtAuth.Infrastructure.Services;

namespace TestInfrastructure;

[TestClass]
public class AuthServiceTests
{
    private AuthService _authService;
    private Mock<AuthDbContext> _mockContext;
    private Mock<Microsoft.Extensions.Configuration.IConfiguration> _mockConfig;

    [TestInitialize]
    public void Setup()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        var context = new AuthDbContext(options);

        // Add a test user with a known password
        var user = new TirsvadWeb.JwtAuth.Domain.Entities.User
        {
            Id = Guid.NewGuid().ToString(),
            UserName = "testuser"
        };
        user.PasswordHash = new Microsoft.AspNetCore.Identity.PasswordHasher<TirsvadWeb.JwtAuth.Domain.Entities.User>().HashPassword(user, "password123");
        context.Users.Add(user);
        context.SaveChanges();

        _mockConfig = new Mock<Microsoft.Extensions.Configuration.IConfiguration>();
        _mockConfig.Setup(c => c["Jwt:Token"]).Returns("super_secret_key_1234567890123456super_secret_key_12345678901234");
        _mockConfig.Setup(c => c["Jwt:Issuer"]).Returns("TestIssuer");
        _mockConfig.Setup(c => c["Jwt:Audience"]).Returns("TestAudience");

        _authService = new AuthService(context, _mockConfig.Object);
    }

    [TestMethod]
    public async Task LoginAsync_ValidCredentials_ReturnsTokenResponse()
    {
        // Arrange
        var request = new UserDto
        {
            UserName = "testuser",
            Password = "password123"
        };

        // Act
        var result = await _authService.LoginAsync(request);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsFalse(string.IsNullOrEmpty(result.AccessToken));
        Assert.IsFalse(string.IsNullOrEmpty(result.RefreshToken));
    }
}