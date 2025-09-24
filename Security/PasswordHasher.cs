using System.Security.Cryptography;

namespace SafeVault.Security
{
    /// <summary>
    /// Handles password hashing and verification according to OWASP guidelines
    /// </summary>
    public static class PasswordHasher
    {
        private static readonly int SALT_SIZE = 32;
        private static readonly int HASH_SIZE = 32;
        private static readonly int ITERATIONS = 100000;

        public static (string Hash, string Salt) HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            byte[] salt = new byte[SALT_SIZE];
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

        private static byte[] GetHash(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(HASH_SIZE);
            }
        }
    }
}