using Microsoft.AspNetCore.Identity;
using SafeVault.Models;

namespace SafeVault.Services;

public interface IAuthService
{
    Task<(bool success, string message)> RegisterUserAsync(string email, string password);
    Task<(bool success, string message, ApplicationUser? user)> ValidateUserAsync(string email, string password);
    Task<bool> ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword);
}

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPasswordHashService _passwordHashService;
    private readonly int _maxFailedAttempts = 5;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        IPasswordHashService passwordHashService)
    {
        _userManager = userManager;
        _passwordHashService = passwordHashService;
    }

    public async Task<(bool success, string message)> RegisterUserAsync(string email, string password)
    {
        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser != null)
        {
            return (false, "User already exists");
        }

        var salt = _passwordHashService.GenerateSalt();
        var hashedPassword = _passwordHashService.HashPassword(password, salt);

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            PasswordSalt = salt,
            CreatedAt = DateTime.UtcNow,
            LastPasswordChangeDate = DateTime.UtcNow,
            EmailConfirmed = false // Require email confirmation
        };

        var result = await _userManager.CreateAsync(user, hashedPassword);
        if (!result.Succeeded)
        {
            return (false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        return (true, "User registered successfully");
    }

    public async Task<(bool success, string message, ApplicationUser? user)> ValidateUserAsync(string email, string password)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return (false, "Invalid credentials", null);
        }

        if (user.IsLocked || (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow))
        {
            return (false, "Account is locked", null);
        }

        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            return (false, "Email not confirmed", null);
        }

        var passwordValid = _passwordHashService.VerifyPassword(password, 
            await _userManager.GetPasswordHashAsync(user), user.PasswordSalt);

        if (!passwordValid)
        {
            user.FailedLoginAttempts++;
            user.LastLoginAttempt = DateTime.UtcNow;

            if (user.FailedLoginAttempts >= _maxFailedAttempts)
            {
                user.IsLocked = true;
                user.LockoutEnd = DateTime.UtcNow.AddMinutes(30); // 30-minute lockout
            }

            await _userManager.UpdateAsync(user);
            return (false, "Invalid credentials", null);
        }

        // Reset failed attempts on successful login
        user.FailedLoginAttempts = 0;
        user.LastLoginAttempt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return (true, "Authentication successful", user);
    }

    public async Task<bool> ChangePasswordAsync(ApplicationUser user, string currentPassword, string newPassword)
    {
        // Verify current password first
        if (!_passwordHashService.VerifyPassword(currentPassword, 
            await _userManager.GetPasswordHashAsync(user), user.PasswordSalt))
        {
            return false;
        }

        // Generate new salt and hash for the new password
        var newSalt = _passwordHashService.GenerateSalt();
        var newHashedPassword = _passwordHashService.HashPassword(newPassword, newSalt);

        // Update password and related fields
        user.PasswordSalt = newSalt;
        user.LastPasswordChangeDate = DateTime.UtcNow;
        user.RequirePasswordChange = false;

        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newHashedPassword);
        return result.Succeeded;
    }
}