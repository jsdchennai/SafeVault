
using Microsoft.Data.SqlClient;

public class AuthService
{
    public bool LoginUser(string username, string password)
{
    string allowedSpecialCharactersForPassword = "!@#$%^&*()";

    // First check for basic input validation
    if (!ValidationHelpers.IsValidInput(username) ||
        !ValidationHelpers.IsValidInput(password, allowedSpecialCharactersForPassword))
    {
        return false; // Basic validation failed
    }

    // Check for XSS attempts
    if (!ValidationHelpers.IsValidXSSInput(username) || !ValidationHelpers.IsValidXSSInput(password))
    {
        return false; // XSS validation failed
    }

    // Sanitize inputs before using them
    username = ValidationHelpers.SanitizeInput(username);
    password = ValidationHelpers.SanitizeInput(password);

    using (var connection = new SqlConnection("YourConnectionStringHere"))
    {
        string query = "SELECT COUNT(1) FROM Users WHERE Username = @Username AND Password = @Password";
        using (var command = new SqlCommand(query, connection))
        {
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@Password", password);

            connection.Open();
            int count = (int)command.ExecuteScalar();
            return count > 0;
        }
    }
}

}