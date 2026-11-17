using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Sequrus;

/// <summary>
/// AES-256-GCM implementation of <see cref="ISequrus"/>.
/// Value format: <c>sq1:</c> + base64url(keyId[4] | nonce[12] | tag[16] | ciphertext).
/// </summary>
/// <remarks>
/// The first key encrypts; every key can decrypt. This allows key rotation:
/// put the new key first, keep the old ones until all values are re-encrypted.
/// </remarks>
public sealed partial class SequrusCipher : ISequrus
{
    /// <summary>Default environment variable with the key list.</summary>
    public const string EnvironmentVariable = "SEQURUS_KEY";

    /// <summary>Prefix of every encrypted value.</summary>
    public const string Prefix = "sq1:";

    private const int KeyIdSize = 4;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int HeaderSize = KeyIdSize + NonceSize + TagSize;
    private const char KeySeparator = ',';

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly KeyEntry[] _keys;

    /// <summary>Creates a cipher from base64 keys of 32 bytes each. The first key encrypts.</summary>
    /// <exception cref="ArgumentException">No keys, or a key is not base64 of 32 bytes.</exception>
    /// <exception cref="PlatformNotSupportedException">AES-GCM is not available on this platform.</exception>
    public SequrusCipher(IEnumerable<string> base64Keys)
    {
        ArgumentNullException.ThrowIfNull(base64Keys);
        if (!AesGcm.IsSupported)
        {
            throw new PlatformNotSupportedException("AES-GCM is not supported on this platform.");
        }

        _keys = base64Keys.Select((k, i) => KeyEntry.Parse(k, i)).ToArray();
        if (_keys.Length == 0)
        {
            throw new ArgumentException("At least one key is required.", nameof(base64Keys));
        }
    }

    /// <inheritdoc cref="SequrusCipher(IEnumerable{string})"/>
    public SequrusCipher(params string[] base64Keys) : this((IEnumerable<string>)base64Keys)
    {
    }

    /// <summary>Parses a comma-separated key list, e.g. <c>newKey,oldKey</c>.</summary>
    public static SequrusCipher Parse(string keyList)
    {
        ArgumentNullException.ThrowIfNull(keyList);
        return new SequrusCipher(keyList.Split(KeySeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>Reads the key list from an environment variable (default <c>SEQURUS_KEY</c>).</summary>
    /// <exception cref="InvalidOperationException">The variable is not set.</exception>
    public static SequrusCipher FromEnvironment(string variable = EnvironmentVariable)
    {
        var value = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Environment variable '{variable}' is not set.");
        }

        return Parse(value);
    }

    /// <summary>Returns <see langword="true"/> when the value looks like an <c>sq1:</c> token. Does not check the key.</summary>
    public static bool IsEncrypted([NotNullWhen(true)] string? value) =>
        value is not null && WholeTokenRegex().IsMatch(value);

    /// <inheritdoc/>
    public string Encrypt(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var bytes = StrictUtf8.GetBytes(plaintext);
        try
        {
            return Encrypt(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <inheritdoc/>
    public string Encrypt(ReadOnlySpan<byte> plaintext)
    {
        var key = _keys[0];
        var blob = new byte[HeaderSize + plaintext.Length];
        var span = blob.AsSpan();
        key.Id.CopyTo(span);
        var nonce = span.Slice(KeyIdSize, NonceSize);
        var tag = span.Slice(KeyIdSize + NonceSize, TagSize);
        RandomNumberGenerator.Fill(nonce);

        using (var aes = new AesGcm(key.Material, TagSize))
        {
            aes.Encrypt(nonce, plaintext, span[HeaderSize..], tag, AssociatedData(key.Id));
        }

        return Prefix + Base64Url.Encode(blob);
    }

    /// <inheritdoc/>
    public string Decrypt(string ciphertext)
    {
        var bytes = DecryptBytes(ciphertext);
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new CryptographicException("Decrypted value is not valid UTF-8 text; use DecryptBytes.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <inheritdoc/>
    public byte[] DecryptBytes(string ciphertext) =>
        TryDecryptCore(ciphertext, out var plaintext)
            ? plaintext
            : throw new CryptographicException("Value cannot be decrypted: wrong key, corrupted data or not an sq1: value.");

    /// <inheritdoc/>
    public bool TryDecrypt(string? ciphertext, [NotNullWhen(true)] out string? plaintext)
    {
        plaintext = null;
        if (!TryDecryptCore(ciphertext, out var bytes))
        {
            return false;
        }

        try
        {
            plaintext = StrictUtf8.GetString(bytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <inheritdoc/>
    public string DecryptConnectionString(string connectionString)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        return ReplaceTokens(connectionString, Decrypt);
    }

    /// <inheritdoc/>
    public string Reencrypt(string ciphertext)
    {
        var bytes = DecryptBytes(ciphertext);
        try
        {
            return Encrypt(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Applies <paramref name="replace"/> to every <c>sq1:</c> token in the text.</summary>
    internal static string ReplaceTokens(string text, Func<string, string> replace) =>
        text.Contains(Prefix, StringComparison.Ordinal)
            ? EmbeddedTokenRegex().Replace(text, m => replace(m.Value))
            : text;

    private bool TryDecryptCore(string? ciphertext, [NotNullWhen(true)] out byte[]? plaintext)
    {
        plaintext = null;
        if (ciphertext is null || !ciphertext.StartsWith(Prefix, StringComparison.Ordinal)
            || !Base64Url.TryDecode(ciphertext.AsSpan(Prefix.Length), out var blob)
            || blob.Length < HeaderSize)
        {
            return false;
        }

        var id = blob.AsSpan(0, KeyIdSize);
        var nonce = blob.AsSpan(KeyIdSize, NonceSize);
        var tag = blob.AsSpan(KeyIdSize + NonceSize, TagSize);
        var data = blob.AsSpan(HeaderSize);

        foreach (var key in _keys)
        {
            if (!id.SequenceEqual(key.Id))
            {
                continue;
            }

            var result = new byte[data.Length];
            try
            {
                using var aes = new AesGcm(key.Material, TagSize);
                aes.Decrypt(nonce, data, tag, result, AssociatedData(key.Id));
                plaintext = result;
                return true;
            }
            catch (CryptographicException)
            {
                // Key-id collision or tampered data: try the next key with the same id.
                CryptographicOperations.ZeroMemory(result);
            }
        }

        return false;
    }

    // Binds the format version and key id to the ciphertext.
    private static byte[] AssociatedData(byte[] keyId) => [.. "sq1"u8, .. keyId];

    [GeneratedRegex(@"\Asq1:[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex WholeTokenRegex();

    // The lookbehind keeps "xsq1:..." (part of another word) untouched.
    [GeneratedRegex(@"(?<![A-Za-z0-9_-])sq1:[A-Za-z0-9_-]+", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex EmbeddedTokenRegex();

    private sealed class KeyEntry
    {
        private KeyEntry(byte[] id, byte[] material)
        {
            Id = id;
            Material = material;
        }

        public byte[] Id { get; }

        public byte[] Material { get; }

        public static KeyEntry Parse(string base64Key, int index)
        {
            // One extra byte detects keys longer than KeySize.
            Span<byte> buffer = stackalloc byte[SequrusKey.KeySize + 1];
            try
            {
                if (string.IsNullOrWhiteSpace(base64Key)
                    || !Convert.TryFromBase64String(base64Key.Trim(), buffer, out var written)
                    || written != SequrusKey.KeySize)
                {
                    // The message never contains the key itself.
                    throw new ArgumentException($"Key #{index} must be base64 of {SequrusKey.KeySize} bytes.", nameof(base64Key));
                }

                var material = buffer[..SequrusKey.KeySize].ToArray();
                return new KeyEntry(SHA256.HashData(material).AsSpan(0, KeyIdSize).ToArray(), material);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
        }
    }
}
