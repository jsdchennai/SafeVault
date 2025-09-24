namespace SafeVault.Models
{
    public class AuthenticationResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime AccessTokenExpiration { get; set; }
        public string TokenType { get; set; } = "Bearer";
    }
}