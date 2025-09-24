using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace SafeVault.Configuration
{
    public class SecureConnectionRequirement : IAuthorizationRequirement { }

    public class SecureConnectionHandler : AuthorizationHandler<SecureConnectionRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            SecureConnectionRequirement requirement)
        {
            if (context.Resource is HttpContext httpContext)
            {
                if (httpContext.Request.IsHttps)
                {
                    context.Succeed(requirement);
                }
                return Task.CompletedTask;
            }

            // If we can't determine if it's HTTPS, fail the requirement
            return Task.CompletedTask;
        }
    }
}