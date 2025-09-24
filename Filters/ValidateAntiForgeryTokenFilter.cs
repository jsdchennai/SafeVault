using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SafeVault.Filters;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class ValidateAntiForgeryTokenFilter : Attribute, IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var antiforgery = context.HttpContext.RequestServices.GetService<IAntiforgery>();
        
        if (antiforgery == null)
        {
            context.Result = new StatusCodeResult(500);
            return;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (Exception)
        {
            context.Result = new BadRequestObjectResult("Invalid anti-forgery token.");
        }
    }
}