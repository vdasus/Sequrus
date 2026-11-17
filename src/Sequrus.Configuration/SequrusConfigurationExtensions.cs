using Microsoft.Extensions.Configuration;

namespace Sequrus.Configuration;

/// <summary>Registers Sequrus decryption in a configuration builder.</summary>
public static class SequrusConfigurationExtensions
{
    /// <summary>
    /// Wraps every source added so far: each <c>sq1:</c> token in their values is decrypted,
    /// including tokens inside connection strings. Call it after the last source you want decrypted.
    /// </summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="sequrus">Cipher to use; <see langword="null"/> means <see cref="Sq.Current"/> (<c>SEQURUS_KEY</c>).</param>
    /// <exception cref="System.Security.Cryptography.CryptographicException">A value cannot be decrypted (thrown on build or reload).</exception>
    public static IConfigurationBuilder AddSequrus(this IConfigurationBuilder builder, ISequrus? sequrus = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var inner = builder.Sources.ToList();
        builder.Sources.Clear();
        return builder.Add(new SequrusConfigurationSource(inner, sequrus));
    }
}
