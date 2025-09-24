using System.ComponentModel.DataAnnotations;
using SafeVault.Validation;

namespace SafeVault.Models;

public class LoginRequest : IValidatableObject
{
    [Required]
    [EmailAddress]
    [StringLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(128, MinimumLength = 8)]
    public string Password { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!InputValidation.IsValidEmail(Email))
        {
            yield return new ValidationResult(
                "Invalid email format.",
                new[] { nameof(Email) }
            );
        }

        if (!InputValidation.IsValidPassword(Password))
        {
            yield return new ValidationResult(
                "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
                new[] { nameof(Password) }
            );
        }

        // Check for injection patterns
        if (InputValidation.ContainsInjectionPatterns(Email) || 
            InputValidation.ContainsInjectionPatterns(Password))
        {
            yield return new ValidationResult(
                "Invalid characters detected in input."
            );
        }
    }
}

public class TokenRequest : IValidatableObject
{
    [Required]
    public string AccessToken { get; set; } = string.Empty;

    [Required]
    public string RefreshToken { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!InputValidation.IsValidJwtToken(AccessToken))
        {
            yield return new ValidationResult(
                "Invalid access token format.",
                new[] { nameof(AccessToken) }
            );
        }

        if (!InputValidation.IsValidToken(RefreshToken))
        {
            yield return new ValidationResult(
                "Invalid refresh token format.",
                new[] { nameof(RefreshToken) }
            );
        }

        // Check for injection patterns
        if (InputValidation.ContainsInjectionPatterns(AccessToken) || 
            InputValidation.ContainsInjectionPatterns(RefreshToken))
        {
            yield return new ValidationResult(
                "Invalid characters detected in input."
            );
        }
    }
}