
using System;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using SafeVault.Security;
using System.Data;
using Microsoft.Extensions.Configuration;

namespace SafeVault.Services
{
    /// <summary>
    /// Handles user authentication and registration with security measures
    /// </summary>
    public class AuthenticationService
    {
        private readonly string _connectionString;
        private const string ValidPasswordSpecialCharacters = "!@#$%^&*()";

        /// <summary>
        /// Initializes a new instance of the AuthenticationService
        /// </summary>
        /// <param name="configuration">The configuration containing connection strings</param>
        /// <exception cref="ArgumentNullException">Thrown when configuration is null</exception>
        public AuthenticationService(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection") 
                ?? throw new ArgumentNullException(nameof(configuration));
        }

        /// <summary>
        /// Authenticates a user with the provided credentials
        /// </summary>
        /// <param name="username">The username to authenticate</param>
        /// <param name="password">The password to verify</param>
        /// <returns>True if authentication is successful, false otherwise</returns>
        public async Task<bool> LoginUserAsync(string username, string password)
        {
            // Input validation
            if (!InputValidator.IsValidInput(username) ||
                !InputValidator.IsValidInput(password, ValidPasswordSpecialCharacters))
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

        /// <summary>
        /// Registers a new user with the provided credentials
        /// </summary>
        /// <param name="username">The username for the new account</param>
        /// <param name="password">The password for the new account</param>
        /// <returns>True if registration is successful, false otherwise</returns>
        public async Task<bool> RegisterUserAsync(string username, string password)
        {
            // Input validation
            if (!InputValidator.IsValidInput(username) ||
                !InputValidator.IsValidInput(password, ValidPasswordSpecialCharacters))
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