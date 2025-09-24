
using Microsoft.Data.SqlClient;

public class AuthService
{
    public bool LoginUser(string username, string password)
{
    string allowedSpecialCharactersForPassword = "!@#$%^&*()";

    if (!ValidationHelpers.IsValidInput(username) ||
        !ValidationHelpers.IsValidInput(password, allowedSpecialCharactersForPassword))
    {
        return false; // Validation failed
    }

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