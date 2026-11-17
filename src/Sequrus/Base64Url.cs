namespace Sequrus;

// shortcut: hand-written base64url because System.Buffers.Text.Base64Url needs .NET 9; switch when net8.0 support is dropped.
internal static class Base64Url
{
    public static string Encode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool TryDecode(ReadOnlySpan<char> text, out byte[] data)
    {
        data = [];
        if (text.IsEmpty || text.Length % 4 == 1)
        {
            return false;
        }

        var padded = new char[(text.Length + 3) / 4 * 4];
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            padded[i] = c switch
            {
                '-' => '+',
                '_' => '/',
                _ when char.IsAsciiLetterOrDigit(c) => c,
                _ => '\0',
            };

            if (padded[i] == '\0')
            {
                return false;
            }
        }

        padded.AsSpan(text.Length).Fill('=');
        var buffer = new byte[padded.Length / 4 * 3];
        if (!Convert.TryFromBase64Chars(padded, buffer, out var written))
        {
            return false;
        }

        data = buffer[..written];
        return true;
    }
}
