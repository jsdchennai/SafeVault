namespace SafeVault.Models
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        public DateTime ExpirationDate { get; set; }
        public string UserId { get; set; } = string.Empty;
        public bool IsUsed { get; set; }
        public bool IsRevoked { get; set; }
        public DateTime CreatedAt { get; set; }
        
        public virtual ApplicationUser User { get; set; } = null!;
    }
}