using System.Diagnostics.CodeAnalysis;

namespace Sequrus;

/// <summary>
/// Encrypts and decrypts values in the <c>sq1:</c> format.
/// </summary>
public interface ISequrus
{
    /// <summary>Encrypts UTF-8 text with the current key. Every call returns a different value.</summary>
    string Encrypt(string plaintext);

    /// <summary>Encrypts raw bytes with the current key.</summary>
    string Encrypt(ReadOnlySpan<byte> plaintext);

    /// <summary>Decrypts an <c>sq1:</c> value to UTF-8 text.</summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Wrong key, corrupted or not an <c>sq1:</c> value.</exception>
    string Decrypt(string ciphertext);

    /// <summary>Decrypts an <c>sq1:</c> value to raw bytes.</summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException">Wrong key, corrupted or not an <c>sq1:</c> value.</exception>
    byte[] DecryptBytes(string ciphertext);

    /// <summary>Decrypts an <c>sq1:</c> value; returns <see langword="false"/> instead of throwing.</summary>
    bool TryDecrypt(string? ciphertext, [NotNullWhen(true)] out string? plaintext);

    /// <summary>
    /// Replaces every <c>sq1:</c> token in the text with its decrypted value and keeps the rest unchanged,
    /// e.g. <c>Server=db;Password=sq1:AbC...</c> becomes <c>Server=db;Password=secret</c>.
    /// </summary>
    string DecryptConnectionString(string connectionString);

    /// <summary>Decrypts with any known key and encrypts again with the current key (key rotation).</summary>
    string Reencrypt(string ciphertext);
}
