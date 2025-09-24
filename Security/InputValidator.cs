using System.Text.RegularExpressions;

namespace SafeVault.Security
{
    /// <summary>
    /// Handles input validation according to OWASP security guidelines
    /// </summary>
    public static class InputValidator
    {
        private const int MAX_INPUT_LENGTH = 1000;

        public static bool IsValidInput(string input, string allowedSpecialCharacters = "", int maxLength = MAX_INPUT_LENGTH)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            if (input.Length > maxLength)
                return false;

            var validCharacters = new HashSet<char>(allowedSpecialCharacters.ToCharArray());
            return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
        }

        public static bool IsValidLength(string input, int maxLength = MAX_INPUT_LENGTH)
        {
            return !string.IsNullOrEmpty(input) && input.Length <= maxLength;
        }
    }
}