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
}