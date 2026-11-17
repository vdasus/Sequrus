using System.Diagnostics.CodeAnalysis;

namespace Sequrus;

/// <summary>Extension methods over <see cref="Sq.Current"/>.</summary>
public static class SequrusExtensions
{
    /// <inheritdoc cref="ISequrus.Encrypt(string)"/>
    public static string SqEncrypt(this string plaintext) => Sq.Current.Encrypt(plaintext);

    /// <inheritdoc cref="ISequrus.Encrypt(ReadOnlySpan{byte})"/>
    public static string SqEncrypt(this byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Sq.Current.Encrypt(plaintext);
    }

    /// <inheritdoc cref="ISequrus.Decrypt(string)"/>
    public static string SqDecrypt(this string ciphertext) => Sq.Current.Decrypt(ciphertext);

    /// <inheritdoc cref="ISequrus.DecryptBytes(string)"/>
    public static byte[] SqDecryptBytes(this string ciphertext) => Sq.Current.DecryptBytes(ciphertext);

    /// <inheritdoc cref="ISequrus.TryDecrypt(string?, out string?)"/>
    public static bool SqTryDecrypt(this string? ciphertext, [NotNullWhen(true)] out string? plaintext) =>
        Sq.Current.TryDecrypt(ciphertext, out plaintext);

    /// <inheritdoc cref="SequrusCipher.IsEncrypted(string?)"/>
    public static bool SqIsEncrypted([NotNullWhen(true)] this string? value) => SequrusCipher.IsEncrypted(value);

    /// <inheritdoc cref="ISequrus.DecryptConnectionString(string)"/>
    public static string SqDecryptConnectionString(this string connectionString) =>
        Sq.Current.DecryptConnectionString(connectionString);

    /// <inheritdoc cref="ISequrus.Reencrypt(string)"/>
    public static string SqReencrypt(this string ciphertext) => Sq.Current.Reencrypt(ciphertext);
}
