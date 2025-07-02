using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TirsvadWeb.JwtAuth.Application.Services;
using TirsvadWeb.JwtAuth.Infrastructure.Data;
using TirsvadWeb.JwtAuth.Infrastructure.Services;

namespace TirsvadWeb.JwtAuth.Infrastructure;

/// <summary>
/// Provides extension methods for registering infrastructure services.
/// </summary>
public static class DependencyInjection
{
    /// <summary>
    /// Registers infrastructure services, including the database context and authentication services, into the dependency injection container.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configuration">The application configuration.</param>
    /// <returns>The updated <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<AuthDbContext>(options =>
            options.UseSqlServer(
                configuration.GetConnectionString("AuthDatabase"),
                b => b.MigrationsAssembly("TirsvadWeb.JwtAuth")
            )
        );

        services.AddScoped<IAuthService, AuthService>();

        return services;
    }
}