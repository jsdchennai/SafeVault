using System;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using SafeVault.Security;
using System.Data;
using Microsoft.Extensions.Configuration;
using BCrypt.Net;

namespace SafeVault.Services
{
    /// <summary>
    /// Handles user authentication and registration with BCrypt security measures
    /// </summary>
    public class AuthenticationService
    {
        private readonly string _connectionString;
        private const string ValidPasswordSpecialCharacters = "!@#$%^&*()";
        private const int MinPasswordLength = 8;
        private const int MaxPasswordLength = 128;
        private const int MaxLoginAttempts = 5;
        private const int LockoutDurationMinutes = 30;

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
        /// <returns>A tuple containing success status and any error message</returns>
        public async Task<(bool Success, string ErrorMessage)> LoginUserAsync(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                return (false, "Username and password are required");

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                string query = @"
                    SELECT 
                        PasswordHash,
                        LoginAttempts,
                        IsLocked,
                        LockoutEnd
                    FROM Users 
                    WHERE Username = @Username";

                using var command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Username", username);

                using var reader = await command.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                    return (false, "Invalid username or password");

                string storedHash = reader.GetString(0);
                int loginAttempts = reader.GetInt32(1);
                bool isLocked = reader.GetBoolean(2);
                DateTime? lockoutEnd = reader.IsDBNull(3) ? null : reader.GetDateTime(3);

                // Check if account is locked
                if (isLocked && lockoutEnd.HasValue && lockoutEnd.Value > DateTime.UtcNow)
                {
                    TimeSpan remaining = lockoutEnd.Value - DateTime.UtcNow;
                    return (false, $"Account is locked. Try again in {Math.Ceiling(remaining.TotalMinutes)} minutes");
                }

                // Verify password using our BCrypt wrapper
                bool isValidPassword = PasswordHasher.VerifyPassword(password, storedHash);

                // Update login attempts
                await UpdateLoginAttemptsAsync(connection, username, isValidPassword);

                // Check if password hash needs upgrading
                if (isValidPassword && PasswordHasher.NeedsUpgrade(storedHash))
                {
                    // Hash the password with new work factor and update database
                    string newHash = PasswordHasher.HashPassword(password);
                    await UpdatePasswordHashAsync(connection, username, newHash);
                }

                if (!isValidPassword)
                {
                    int remainingAttempts = MaxLoginAttempts - (loginAttempts + 1);
                    if (remainingAttempts <= 0)
                        return (false, "Account has been locked due to too many failed attempts");
                    
                    return (false, $"Invalid password. {remainingAttempts} attempts remaining");
                }

                return (true, "Login successful");
            }
            catch (Exception ex)
            {
                return (false, $"An error occurred: {ex.Message}");
            }
        }

        /// <summary>
        /// Registers a new user with secure password hashing using BCrypt
        /// </summary>
        /// <param name="username">The username for the new account</param>
        /// <param name="password">The password for the new account</param>
        /// <returns>A tuple containing success status and any error message</returns>
        public async Task<(bool Success, string ErrorMessage)> RegisterUserAsync(string username, string password)
        {
            // Basic validation
            if (string.IsNullOrWhiteSpace(username))
                return (false, "Username cannot be empty");

            if (string.IsNullOrWhiteSpace(password))
                return (false, "Password cannot be empty");

            if (password.Length < MinPasswordLength)
                return (false, $"Password must be at least {MinPasswordLength} characters long");

            if (password.Length > MaxPasswordLength)
                return (false, $"Password cannot exceed {MaxPasswordLength} characters");

            // Input validation
            if (!InputValidator.IsValidInput(username) ||
                !InputValidator.IsValidInput(password, ValidPasswordSpecialCharacters))
            {
                return (false, "Invalid characters in username or password");
            }

            // XSS protection
            if (!XssProtection.IsValidInput(username) || !XssProtection.IsValidInput(password))
            {
                return (false, "Potentially malicious content detected");
            }

            // Sanitize username (password should not be sanitized before hashing)
            username = XssProtection.SanitizeInput(username);

            try
            {
                // Hash the password using our BCrypt wrapper
                string hashedPassword = PasswordHasher.HashPassword(password);

                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                // Check if username already exists
                if (await UsernameExistsAsync(connection, username))
                {
                    return (false, "Username already exists");
                }

                string query = @"
                    INSERT INTO Users (
                        Username,
                        PasswordHash,
                        CreatedAt,
                        LastLoginAttempt,
                        LoginAttempts,
                        IsLocked,
                        LockoutEnd
                    ) VALUES (
                        @Username,
                        @PasswordHash,
                        @CreatedAt,
                        NULL,
                        0,
                        0,
                        NULL
                    )";

                using var command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Username", username);
                command.Parameters.AddWithValue("@PasswordHash", hashedPassword);
                command.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);

                await command.ExecuteNonQueryAsync();
                return (true, "User registered successfully");
            }
            catch (SqlException ex)
            {
                return (false, $"Database error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"An error occurred: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks if a username already exists in the database
        /// </summary>
        private async Task<bool> UsernameExistsAsync(SqlConnection connection, string username)
        {
            string query = "SELECT COUNT(1) FROM Users WHERE Username = @Username";
            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);

            int count = Convert.ToInt32(await command.ExecuteScalarAsync());
            return count > 0;
        }

        /// <summary>
        /// Updates the password hash for a user when the hashing algorithm needs upgrading
        /// </summary>
        private async Task UpdatePasswordHashAsync(SqlConnection connection, string username, string newHash)
        {
            string query = @"
                UPDATE Users 
                SET PasswordHash = @PasswordHash 
                WHERE Username = @Username";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@PasswordHash", newHash);

            await command.ExecuteNonQueryAsync();
        }

        /// <summary>
        /// Updates login attempts and handles account locking
        /// </summary>
        private async Task UpdateLoginAttemptsAsync(SqlConnection connection, string username, bool wasSuccessful)
        {
            string query;
            if (wasSuccessful)
            {
                query = @"
                    UPDATE Users 
                    SET LoginAttempts = 0,
                        LastLoginAttempt = @CurrentTime,
                        IsLocked = 0,
                        LockoutEnd = NULL
                    WHERE Username = @Username";
            }
            else
            {
                query = @"
                    UPDATE Users 
                    SET LoginAttempts = LoginAttempts + 1,
                        LastLoginAttempt = @CurrentTime,
                        IsLocked = CASE 
                            WHEN LoginAttempts + 1 >= @MaxAttempts THEN 1 
                            ELSE 0 
                        END,
                        LockoutEnd = CASE 
                            WHEN LoginAttempts + 1 >= @MaxAttempts 
                            THEN DATEADD(minute, @LockoutDuration, @CurrentTime)
                            ELSE NULL 
                        END
                    WHERE Username = @Username";
            }

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@CurrentTime", DateTime.UtcNow);
            command.Parameters.AddWithValue("@MaxAttempts", MaxLoginAttempts);
            command.Parameters.AddWithValue("@LockoutDuration", LockoutDurationMinutes);

            await command.ExecuteNonQueryAsync();
        }
    }
}