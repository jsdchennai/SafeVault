
using System;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using SafeVault.Security;
using System.Data;
using Microsoft.Extensions.Configuration;

namespace SafeVault.Services
{
    public class AuthService
    {
        private readonly string _connectionString;
        private const string AllowedPasswordCharacters = "!@#$%^&*()";

        public AuthService(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection") 
                ?? throw new ArgumentNullException(nameof(configuration));
        }

        public async Task<bool> LoginUserAsync(string username, string password)
        {
            // Input validation
            if (!InputValidator.IsValidInput(username) ||
                !InputValidator.IsValidInput(password, AllowedPasswordCharacters))
            {
                return false;
            }

            // XSS protection
            if (!XssProtection.IsValidInput(username) || !XssProtection.IsValidInput(password))
            {
                return false;
            }

            // Sanitize inputs
            username = XssProtection.SanitizeInput(username);
            password = XssProtection.SanitizeInput(password);

            using (var connection = new SqlConnection(_connectionString))
            {
                string query = "SELECT PasswordHash, PasswordSalt FROM Users WHERE Username = @Username";
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);

                    await connection.OpenAsync();
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!await reader.ReadAsync())
                            return false;

                        string storedHash = reader.GetString(0);
                        string storedSalt = reader.GetString(1);

                        return PasswordHasher.VerifyPassword(password, storedHash, storedSalt);
                    }
                }
            }
        }

        public async Task<bool> RegisterUserAsync(string username, string password)
        {
            // Input validation
            if (!InputValidator.IsValidInput(username) ||
                !InputValidator.IsValidInput(password, AllowedPasswordCharacters))
            {
                return false;
            }

            // XSS protection
            if (!XssProtection.IsValidInput(username) || !XssProtection.IsValidInput(password))
            {
                return false;
            }

            // Sanitize inputs
            username = XssProtection.SanitizeInput(username);
            password = XssProtection.SanitizeInput(password);

            // Hash the password
            var (hash, salt) = PasswordHasher.HashPassword(password);

            using (var connection = new SqlConnection(_connectionString))
            {
                string query = @"
                    INSERT INTO Users (Username, PasswordHash, PasswordSalt, CreatedAt)
                    VALUES (@Username, @PasswordHash, @PasswordSalt, @CreatedAt)";

                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@PasswordHash", hash);
                    command.Parameters.AddWithValue("@PasswordSalt", salt);
                    command.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);

                    try
                    {
                        await connection.OpenAsync();
                        return await command.ExecuteNonQueryAsync() > 0;
                    }
                    catch (SqlException)
                    {
                        return false; // Username might already exist or other DB error
                    }
                }
            }
        }
    }
}