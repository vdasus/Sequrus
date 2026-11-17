using System.Security.Cryptography;

namespace Sequrus;

/// <summary>Creates keys for <see cref="SequrusCipher"/>.</summary>
public static class SequrusKey
{
    /// <summary>Key size in bytes (AES-256).</summary>
    public const int KEY_SIZE = 32;

    /// <summary>Minimum salt size in bytes for <see cref="DeriveFromPassword"/>.</summary>
    public const int MIN_SALT_SIZE = 16;

    /// <summary>Default PBKDF2-SHA256 iteration count (OWASP 2023 recommendation).</summary>
    public const int DEFAULT_ITERATIONS = 600_000;

    /// <summary>Generates a random key as base64.</summary>
    public static string Generate() => ToBase64AndZero(RandomNumberGenerator.GetBytes(KEY_SIZE));

    /// <summary>Generates a random salt for <see cref="DeriveFromPassword"/>.</summary>
    public static byte[] GenerateSalt() => RandomNumberGenerator.GetBytes(MIN_SALT_SIZE);

    /// <summary>
    /// Derives a key from a password with PBKDF2-SHA256. The same password, salt and iteration count
    /// always give the same key, so keep the salt next to the encrypted data (it is not secret).
    /// </summary>
    public static string DeriveFromPassword(string password, byte[] salt, int iterations = DEFAULT_ITERATIONS)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(salt);
        if (salt.Length < MIN_SALT_SIZE)
        {
            throw new ArgumentException($"Salt must be at least {MIN_SALT_SIZE} bytes.", nameof(salt));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 100_000);
        return ToBase64AndZero(Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, KEY_SIZE));
    }

    private static string ToBase64AndZero(byte[] key)
    {
        try
        {
            return Convert.ToBase64String(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
