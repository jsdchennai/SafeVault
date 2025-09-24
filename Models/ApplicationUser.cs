using Microsoft.AspNetCore.Identity;

namespace SafeVault.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Security-related properties
        public byte[] PasswordSalt { get; set; } = Array.Empty<byte>();
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAttempt { get; set; }
        public DateTime? LastPasswordChangeDate { get; set; }
        public int FailedLoginAttempts { get; set; }
        public bool RequirePasswordChange { get; set; }
        public bool IsLocked { get; set; }

        // Token-related properties
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        // Inheriting LockoutEnd from IdentityUser for temporary lockouts
    }
}