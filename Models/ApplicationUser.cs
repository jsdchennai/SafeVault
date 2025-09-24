using Microsoft.AspNetCore.Identity;

namespace SafeVault.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Add custom user properties here
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAttempt { get; set; }
        public bool IsLocked { get; set; }
        // Inheriting LockoutEnd from IdentityUser
    }
}