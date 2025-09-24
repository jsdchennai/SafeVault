using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Models;
using SafeVault.Services;
using SafeVault.Validation;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("token")] // Rate limiting policy
public class TokenController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ITokenService _tokenService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly TimeSpan _refreshTokenLifetime = TimeSpan.FromDays(7); // 7 days for refresh token

    public TokenController(
        IAuthService authService,
        ITokenService tokenService,
        UserManager<ApplicationUser> userManager)
    {
        _authService = authService;
        _tokenService = tokenService;
        _userManager = userManager;
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Additional sanitization
        var sanitizedEmail = InputValidation.SanitizeEmail(request.Email);
        var (success, message, user) = await _authService.ValidateUserAsync(sanitizedEmail, request.Password);
        
        if (!success || user == null)
        {
            return BadRequest(message);
        }

        var roles = await _userManager.GetRolesAsync(user);
        var accessToken = _tokenService.GenerateAccessToken(user, roles);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // Save refresh token
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.Add(_refreshTokenLifetime);
        await _userManager.UpdateAsync(user);

        return Ok(new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh([FromBody] TokenRequest tokens)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var principal = _tokenService.GetPrincipalFromExpiredToken(tokens.AccessToken);
        if (principal == null)
        {
            return BadRequest("Invalid access token");
        }

        var user = await _userManager.FindByNameAsync(principal.Identity!.Name!);
        if (user == null || 
            user.RefreshToken != tokens.RefreshToken || 
            user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return BadRequest("Invalid refresh token or token expired");
        }

        var roles = await _userManager.GetRolesAsync(user);
        var newAccessToken = _tokenService.GenerateAccessToken(user, roles);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        // Save new refresh token
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.Add(_refreshTokenLifetime);
        await _userManager.UpdateAsync(user);

        return Ok(new TokenResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }

    [Authorize]
    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke()
    {
        var username = User.Identity!.Name;
        var user = await _userManager.FindByNameAsync(username!);
        if (user == null)
        {
            return BadRequest();
        }

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await _userManager.UpdateAsync(user);

        return NoContent();
    }
}