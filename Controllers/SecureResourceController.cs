using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Constants;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize] // Base authorization requirement
    public class SecureResourceController : ControllerBase
    {
        [HttpGet("public")]
        [AllowAnonymous]
        public IActionResult GetPublicResource()
        {
            return Ok(new { message = "This is a public resource" });
        }

        [HttpGet("user")]
        [Authorize(Policy = PolicyNames.RequireUserRole)]
        public IActionResult GetUserResource()
        {
            return Ok(new { message = "This is a user-level resource" });
        }

        [HttpGet("admin")]
        [Authorize(Policy = PolicyNames.RequireAdminRole)]
        public IActionResult GetAdminResource()
        {
            return Ok(new { message = "This is an admin-level resource" });
        }

        [HttpGet("elevated")]
        [Authorize(Policy = PolicyNames.RequireElevatedRights)]
        public IActionResult GetElevatedResource()
        {
            return Ok(new { message = "This is a resource requiring elevated rights" });
        }

        [HttpGet("verified")]
        [Authorize(Policy = PolicyNames.RequireVerifiedEmail)]
        public IActionResult GetVerifiedResource()
        {
            return Ok(new { message = "This is a resource requiring verified email" });
        }

        [HttpGet("secure")]
        [Authorize(Policy = PolicyNames.RequireSecureConnection)]
        public IActionResult GetSecureResource()
        {
            return Ok(new { message = "This is a resource requiring HTTPS" });
        }

        [HttpGet("combined")]
        [Authorize(Policy = PolicyNames.RequireAdminRole)]
        [Authorize(Policy = PolicyNames.RequireVerifiedEmail)]
        [Authorize(Policy = PolicyNames.RequireSecureConnection)]
        public IActionResult GetCombinedResource()
        {
            return Ok(new { message = "This is a resource requiring multiple policies" });
        }
    }
}