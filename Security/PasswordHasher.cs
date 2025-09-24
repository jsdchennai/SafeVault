using System.Security.Cryptography;
using System.Text;

namespace SafeVault.Security
{
    /// <summary>
    /// Handles password hashing and verification according to OWASP guidelines
    /// </summary>
    public static class PasswordHasher
    {
        private const int DefaultSaltSizeInBytes = 32;
        private const int DefaultHashSizeInBytes = 32;
        private const int DefaultIterationCount = 100000;

        /// <summary>
        /// Generates a cryptographically secure hash and salt for a password
        /// </summary>
        /// <param name="password">The password to hash</param>
        /// <returns>A tuple containing the Base64-encoded hash and salt</returns>
        /// <exception cref="ArgumentNullException">Thrown when password is null or empty</exception>
        public static (string Hash, string Salt) HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            byte[] salt = new byte[DefaultSaltSizeInBytes];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] hash = GetHash(password, salt);
            return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
        }

        public static bool VerifyPassword(string password, string storedHash, string storedSalt)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash) || string.IsNullOrEmpty(storedSalt))
                return false;

            try
            {
                byte[] hash = Convert.FromBase64String(storedHash);
                byte[] salt = Convert.FromBase64String(storedSalt);

                byte[] computedHash = GetHash(password, salt);
                return hash.SequenceEqual(computedHash);
            }
            catch
            {
                return false; // Invalid hash or salt format
            }
        }

        /// <summary>
        /// Generates a hash using PBKDF2 with SHA256
        /// </summary>
        /// <param name="password">The password to hash</param>
        /// <param name="salt">The salt to use in the hashing process</param>
        /// <returns>The computed hash</returns>
        private static byte[] GetHash(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(
                Encoding.UTF8.GetBytes(password), 
                salt, 
                DefaultIterationCount, 
                HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(DefaultHashSizeInBytes);
            }
        }
    }
}