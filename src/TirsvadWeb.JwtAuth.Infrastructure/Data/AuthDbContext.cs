using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TirsvadWeb.JwtAuth.Domain.Entities;

namespace TirsvadWeb.JwtAuth.Infrastructure.Data;

/// <summary>
/// Represents the Entity Framework database context for authentication, including user identity management.
/// </summary>
public class AuthDbContext : IdentityDbContext<ApplicationUser>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthDbContext"/> class using the specified options.
    /// </summary>
    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    /// <summary>
    /// Configures the schema needed for the identity framework and customizes the Users table mapping.
    /// </summary>
    /// <param name="modelBuilder">The builder being used to construct the model for this context.</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<ApplicationUser>().ToTable("Users");
    }
}