using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TirsvadWeb.JwtAuth.Domain.Entities;

namespace TirsvadWeb.JwtAuth.Infrastructure.Data;

public class AuthDbContext(DbContextOptions<AuthDbContext> options) : IdentityDbContext<User>(options)
{
    //public override DbSet<User> Users { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<User>().ToTable("Users");
    }
}