using System.Web;
using System.Text.RegularExpressions;

namespace SafeVault.Security
{
    /// <summary>
    /// Handles Cross-Site Scripting (XSS) prevention according to OWASP guidelines
    /// </summary>
    public static class XssProtection
    {
        private const int MAX_INPUT_LENGTH = 1000;
        private static readonly string[] XssPatterns = new[]
        {
            @"<script[^>]*>",
            @"<iframe[^>]*>",
            @"<embed[^>]*>",
            @"<object[^>]*>",
            @"javascript:",
            @"vbscript:",
            @"data:",
            @"onload=",
            @"onerror=",
            @"onclick=",
            @"onmouseover=",
            @"onfocus=",
            @"onblur=",
            @"eval\(",
            @"setTimeout\(",
            @"setInterval\(",
            @"document\.cookie",
            @"document\.write",
            @"document\.location",
            @"window\.location",
            @"new\s+Function\(",
            @"alert\(",
            @"\[\s*stringify\s*\]",
            @"with\s*\("
        };

        public static bool IsValidInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return true;

            if (input.Length > MAX_INPUT_LENGTH)
                return false;

            input = input.ToLower();
            return !XssPatterns.Any(pattern =>
                Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled));
        }

        public static string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            if (input.Length > MAX_INPUT_LENGTH)
                input = input.Substring(0, MAX_INPUT_LENGTH);

            input = HttpUtility.HtmlEncode(input);
            input = RemoveDangerousCharacters(input);
            input = RemoveSqlInjectionPatterns(input);

            return input;
        }

        private static string RemoveDangerousCharacters(string input)
        {
            return Regex.Replace(input, @"[\u0000-\u001F\u007F-\u009F\u2028\u2029\uFFF0-\uFFFF]", string.Empty);
        }

        private static string RemoveSqlInjectionPatterns(string input)
        {
            return Regex.Replace(input, @"[;']|-{2}", string.Empty);
        }
    }
}