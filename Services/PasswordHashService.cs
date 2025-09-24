using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace SafeVault.Services;

public interface IPasswordHashService
{
    string HashPassword(string password, byte[] salt);
    byte[] GenerateSalt();
    bool VerifyPassword(string password, string hash, byte[] salt);
}

public class PasswordHashService : IPasswordHashService
{
    private const int SaltSize = 128 / 8; // 128 bits
    private const int HashSize = 256 / 8; // 256 bits
    private const int Iterations = 100000; // Number of iterations for PBKDF2

    public string HashPassword(string password, byte[] salt)
    {
        // Generate the hash using PBKDF2 with HMAC-SHA256
        byte[] hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: Iterations,
            numBytesRequested: HashSize);

        return Convert.ToBase64String(hash);
    }

    public byte[] GenerateSalt()
    {
        // Generate a cryptographically secure random salt
        byte[] salt = new byte[SaltSize];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        return salt;
    }

    public bool VerifyPassword(string password, string hash, byte[] salt)
    {
        string computedHash = HashPassword(password, salt);
        return computedHash.Equals(hash, StringComparison.OrdinalIgnoreCase);
    }
}