namespace Sequrus;

/// <summary>
/// Process-wide <see cref="ISequrus"/> used by the <c>Sq*</c> extension methods.
/// </summary>
/// <remarks>
/// By default the key list is read once from <c>SEQURUS_KEY</c> on first use and cached.
/// A missing variable throws on every call until it is set; the failure is not cached.
/// </remarks>
public static class Sq
{
    private static ISequrus? s_current;

    /// <summary>The configured instance, or one created from <c>SEQURUS_KEY</c>.</summary>
    public static ISequrus Current => Volatile.Read(ref s_current) ?? Initialize();

    /// <summary>
    /// Sets the instance used by the extension methods.
    /// Pass <see langword="null"/> to read <c>SEQURUS_KEY</c> again on next use.
    /// </summary>
    public static void Configure(ISequrus? sequrus) => Volatile.Write(ref s_current, sequrus);

    private static ISequrus Initialize()
    {
        var created = SequrusCipher.FromEnvironment();
        return Interlocked.CompareExchange(ref s_current, created, null) ?? created;
    }
}
