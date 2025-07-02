using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TirsvadWeb.JwtAuth.Application.Services;
using TirsvadWeb.JwtAuth.Infrastructure.Data;
using TirsvadWeb.JwtAuth.Infrastructure.Services;

namespace TirsvadWeb.JwtAuth.Infrastructure;

public static class DependencyInjection
{
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
