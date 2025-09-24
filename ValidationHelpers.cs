using System.Web;
using System.Text.RegularExpressions;

public static class ValidationHelpers
{
    // Validates input: allows letters, digits, and specified special characters
    public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;

        var validCharacters = new HashSet<char>(allowedSpecialCharacters.ToCharArray());

        return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
    }

    public static bool IsValidXSSInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        // Check for common XSS patterns
        var xssPatterns = new[]
        {
            @"<script[^>]*>",
            @"<iframe[^>]*>",
            @"javascript:",
            @"onload=",
            @"onerror=",
            @"onclick=",
            @"onmouseover=",
            @"eval\(",
            @"document\.cookie"
        };

        // Convert to lowercase for case-insensitive checking
        input = input.ToLower();

        // Check if any XSS pattern is found
        foreach (var pattern in xssPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                return false;
        }

        return true;
    }

    public static string SanitizeInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        // HTML encode the input to prevent XSS
        input = HttpUtility.HtmlEncode(input);

        // Remove potentially dangerous Unicode characters
        input = Regex.Replace(input, @"[\u0000-\u001F\u007F-\u009F]", string.Empty);

        return input;
    }

    public static void TestXssInput()
    {
        string maliciousInput = "<script>alert('XSS');</script>";
        bool isValid = IsValidXSSInput(maliciousInput);
        Console.WriteLine(isValid ? "XSS Test Failed" : "XSS Test Passed");
    }
}