using Microsoft.EntityFrameworkCore;

namespace JwtAuthWebAPI.Enitites.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options): DbContext(options)
    {
        public DbSet<User> Users { get; set; }

    }
}
