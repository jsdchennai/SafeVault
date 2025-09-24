using BCrypt.Net;
using System;

namespace SafeVault.Security
{
    /// <summary>
    /// Handles password hashing and verification using BCrypt according to OWASP guidelines
    /// </summary>
    public static class PasswordHasher
    {
        // BCrypt work factor - higher means more secure but slower
        // 12 is a good balance between security and performance as of 2025
        private const int WorkFactor = 12;

        /// <summary>
        /// Hashes a password using BCrypt with a secure work factor
        /// </summary>
        /// <param name="password">The password to hash</param>
        /// <returns>The BCrypt hash which includes the salt</returns>
        /// <exception cref="ArgumentNullException">Thrown when password is null or empty</exception>
        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            try
            {
                // BCrypt will automatically generate a secure salt and include it in the hash
                return BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to hash password", ex);
            }
        }

        /// <summary>
        /// Verifies a password against a BCrypt hash
        /// </summary>
        /// <param name="password">The password to verify</param>
        /// <param name="hashedPassword">The BCrypt hash to verify against</param>
        /// <returns>True if the password matches the hash, false otherwise</returns>
        public static bool VerifyPassword(string password, string hashedPassword)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword))
                return false;

            try
            {
                // BCrypt.Verify will extract the salt from the hash and perform the comparison
                return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
            }
            catch
            {
                return false; // Invalid hash format or other error
            }
        }

        /// <summary>
        /// Checks if a hash needs to be upgraded based on our current security requirements
        /// </summary>
        /// <param name="hashedPassword">The BCrypt hash to check</param>
        /// <returns>True if the hash should be upgraded, false otherwise</returns>
        public static bool NeedsUpgrade(string hashedPassword)
        {
            if (string.IsNullOrEmpty(hashedPassword) || !hashedPassword.StartsWith("$2"))
                return true; // Not a valid BCrypt hash

            try
            {
                // Generate a test hash to compare settings
                string testHash = BCrypt.Net.BCrypt.HashPassword("test", WorkFactor);
                
                // Compare the version and work factor parts of the hash
                string[] currentParts = hashedPassword.Split('$');
                string[] newParts = testHash.Split('$');
                
                // Check if the format versions match and if the work factor is sufficient
                return currentParts.Length < 4 || newParts.Length < 4 ||
                       currentParts[1] != newParts[1] || // Version mismatch
                       int.Parse(currentParts[2]) < int.Parse(newParts[2]); // Work factor is too low
            }
            catch
            {
                return true; // If we can't parse the hash, it should be upgraded
            }
        }
    }
}