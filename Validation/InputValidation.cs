using System.Text.RegularExpressions;

namespace SafeVault.Validation;

public static class InputValidation
{
    // Email validation pattern based on RFC 5322
    private static readonly Regex EmailRegex = new(
        @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(250));

    // Password validation pattern
    // At least 8 characters, max 128 chars
    // Must contain at least one uppercase letter, one lowercase letter, one number, and one special character
    private static readonly Regex PasswordRegex = new(
        @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,128}$",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    // Token validation pattern for refresh tokens (base64 format)
    private static readonly Regex TokenRegex = new(
        @"^[A-Za-z0-9+/=]{64,}$",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(250));

    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || email.Length > 256)
            return false;

        try
        {
            return EmailRegex.IsMatch(email);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    public static bool IsValidPassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
            return false;

        try
        {
            return PasswordRegex.IsMatch(password);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    public static bool IsValidToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        try
        {
            return TokenRegex.IsMatch(token);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    public static bool IsValidJwtToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        // JWT format validation: three base64url encoded strings separated by dots
        var parts = token.Split('.');
        if (parts.Length != 3)
            return false;

        // Check each part is valid base64url
        foreach (var part in parts)
        {
            if (!IsValidBase64UrlString(part))
                return false;
        }

        return true;
    }

    private static bool IsValidBase64UrlString(string input)
    {
        // Add padding if needed
        string padding = new('=', (4 - input.Length % 4) % 4);
        string toDecode = input
            .Replace('-', '+')
            .Replace('_', '/') + padding;

        try
        {
            Convert.FromBase64String(toDecode);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string SanitizeEmail(string email)
    {
        return email.Trim().ToLowerInvariant();
    }

    public static bool ContainsInjectionPatterns(string input)
    {
        // Check for common SQL injection patterns
        var sqlPatterns = new[]
        {
            "--", ";", "/*", "*/", "@@", "@", "char", "nchar",
            "varchar", "nvarchar", "alter", "begin", "cast",
            "create", "cursor", "declare", "delete", "drop",
            "end", "exec", "execute", "fetch", "insert", "kill",
            "select", "sys", "sysobjects", "syscolumns", "table",
            "update"
        };

        // Check for common XSS patterns
        var xssPatterns = new[]
        {
            "<script", "javascript:", "vbscript:", "onload=",
            "onerror=", "<img", "<iframe", "<object", "<embed",
            "alert(", "eval(", "expression(", "onclick="
        };

        return sqlPatterns.Any(pattern => 
            input.Contains(pattern, StringComparison.OrdinalIgnoreCase)) ||
            xssPatterns.Any(pattern => 
                input.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }
}