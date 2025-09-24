using Microsoft.AspNetCore.Authorization;
using SafeVault.Constants;
using System.Security.Claims;

namespace SafeVault.Configuration
{
    public static class AuthorizationPolicyConfiguration
    {
        public static void ConfigurePolicies(AuthorizationOptions options)
        {
            // Admin role policy
            options.AddPolicy(PolicyNames.RequireAdminRole,
                policy => policy.RequireRole(RoleNames.Admin));

            // User role policy
            options.AddPolicy(PolicyNames.RequireUserRole,
                policy => policy.RequireRole(RoleNames.User));

            // Elevated rights policy (Admin or User role)
            options.AddPolicy(PolicyNames.RequireElevatedRights,
                policy => policy.RequireRole(RoleNames.Admin, RoleNames.User));

            // Verified email policy
            options.AddPolicy(PolicyNames.RequireVerifiedEmail,
                policy => policy
                    .RequireClaim("EmailConfirmed", "true")
                    .RequireAuthenticatedUser());

            // Secure connection policy
            options.AddPolicy(PolicyNames.RequireSecureConnection,
                policy => policy.Requirements.Add(new SecureConnectionRequirement()));
        }
    }
}