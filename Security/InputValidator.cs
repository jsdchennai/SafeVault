using System.Text.RegularExpressions;

namespace SafeVault.Security
{
    /// <summary>
    /// Handles input validation according to OWASP security guidelines
    /// </summary>
    public static class InputValidator
    {
        private const int DefaultMaxInputLength = 1000;

        /// <summary>
        /// Validates if the input string contains only allowed characters
        /// </summary>
        /// <param name="input">The string to validate</param>
        /// <param name="allowedSpecialCharacters">Special characters that are allowed in addition to letters and digits</param>
        /// <param name="maxLength">Maximum allowed length of the input</param>
        /// <returns>True if the input is valid, false otherwise</returns>
        public static bool IsValidInput(string input, string allowedSpecialCharacters = "", int maxLength = DefaultMaxInputLength)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            if (input.Length > maxLength)
                return false;

            var validCharacters = new HashSet<char>(allowedSpecialCharacters.ToCharArray());
            return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
        }

        /// <summary>
        /// Validates if the input string length is within the specified limit
        /// </summary>
        /// <param name="input">The string to validate</param>
        /// <param name="maxLength">Maximum allowed length of the input</param>
        /// <returns>True if the input length is valid, false otherwise</returns>
        public static bool IsValidLength(string input, int maxLength = DefaultMaxInputLength)
        {
            return !string.IsNullOrEmpty(input) && input.Length <= maxLength;
        }
    }
}