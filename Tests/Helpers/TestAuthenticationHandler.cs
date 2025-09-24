using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace SafeVault.Tests.Helpers
{
    public class TestAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public TestAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "testuser@example.com"),
                new Claim(ClaimTypes.NameIdentifier, "testuser-id"),
                new Claim(ClaimTypes.Email, "testuser@example.com")
            };

            // Add roles from context
            if (Context.Request.Headers.TryGetValue("Test-Roles", out var roles))
            {
                foreach (var role in roles.ToString().Split(','))
                {
                    claims.Add(new Claim(ClaimTypes.Role, role.Trim()));
                }
            }

            // Add email verification status
            if (Context.Request.Headers.TryGetValue("Test-EmailVerified", out var emailVerified))
            {
                claims.Add(new Claim("EmailConfirmed", emailVerified.ToString().ToLower()));
            }

            var identity = new ClaimsIdentity(claims, "Test");
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, "Test");

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    public static class TestClaimsProvider
    {
        public static List<Claim> GetClaims(string userId, string email, string[] roles, bool emailVerified = false)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Email, email),
                new Claim("EmailConfirmed", emailVerified.ToString().ToLower())
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            return claims;
        }
    }
}