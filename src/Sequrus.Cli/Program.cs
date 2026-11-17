using System.Security.Cryptography;
using System.Text;
using Optionus;
using Sequrus;

const string KeyNote = "SEQURUS_KEY holds one key or a comma-separated list \"newKey,oldKey\"; the first key encrypts.";
const string SecretNote = "Secrets are never taken from arguments (they would stay in shell history and process lists): "
    + "they are read from a hidden prompt, or from stdin when redirected.";

var usePassword = false;
string? salt = null;

var suite = new CommandSet("sequrus")
{
    "usage: sequrus COMMAND [OPTIONS]",
    "",
    KeyNote,
    SecretNote,
    "",
    new Command("keygen", "Print a new random key, or derive one from a password (PBKDF2-SHA256)")
    {
        Options = new OptionSet
        {
            "usage: sequrus keygen [--password [--salt=SALT]]",
            "",
            { "p|password", "derive the key from a password read from the prompt or stdin", v => usePassword = v != null },
            { "s|salt=", "base64 {SALT} to derive the same key again; a new salt is generated when omitted", v => salt = v },
        },
        Run = rest =>
        {
            NoArguments(rest);
            if (!usePassword)
            {
                if (salt is not null)
                {
                    throw new OptionException("--salt requires --password.", "salt");
                }

                Console.WriteLine(SequrusKey.Generate());
                return;
            }

            var saltBytes = salt is null ? SequrusKey.GenerateSalt() : Convert.FromBase64String(salt);
            var key = SequrusKey.DeriveFromPassword(ReadSecret("Password: "), saltBytes);
            Console.WriteLine($"key:  {key}");
            Console.WriteLine($"salt: {Convert.ToBase64String(saltBytes)}");
        },
    },
    new Command("encrypt", "Encrypt a secret with the first key of SEQURUS_KEY")
    {
        Options = new OptionSet { "usage: sequrus encrypt", "", SecretNote },
        Run = rest =>
        {
            NoArguments(rest);
            Console.WriteLine(SequrusCipher.FromEnvironment().Encrypt(ReadSecret("Secret: ")));
        },
    },
    new Command("decrypt", "Decrypt an sq1: value")
    {
        Options = new OptionSet { "usage: sequrus decrypt", "", "The value is read from the prompt or stdin." },
        Run = rest =>
        {
            NoArguments(rest);
            Console.WriteLine(SequrusCipher.FromEnvironment().Decrypt(ReadSecret("Value: ").Trim()));
        },
    },
    new Command("reencrypt", "Re-encrypt every sq1: token from stdin with the first key, write the text to stdout")
    {
        Options = new OptionSet { "usage: sequrus reencrypt < input > output", "", KeyNote },
        Run = rest =>
        {
            NoArguments(rest);
            var cipher = SequrusCipher.FromEnvironment();
            Console.Write(SequrusCipher.ReplaceTokens(Console.In.ReadToEnd(), cipher.Reencrypt));
        },
    },
};

try
{
    return suite.Run(args);
}
catch (OptionException ex)
{
    Console.Error.WriteLine($"sequrus: {ex.Message}");
    Console.Error.WriteLine("Try `sequrus help' for more information.");
    return 2;
}
catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or ArgumentException or FormatException)
{
    // Messages from Sequrus never contain keys or plaintext.
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

// Rejects stray arguments without echoing them: a stray argument may be a secret typed by mistake.
static void NoArguments(IEnumerable<string> rest)
{
    if (rest.Any())
    {
        throw new OptionException("Unexpected argument. " + SecretNote, "argument");
    }
}

static string ReadSecret(string prompt)
{
    if (Console.IsInputRedirected)
    {
        // Drop only the trailing line break added by echo/heredoc.
        return Console.In.ReadToEnd().TrimEnd('\r', '\n');
    }

    Console.Error.Write(prompt);
    var sb = new StringBuilder();
    while (true)
    {
        var k = Console.ReadKey(intercept: true);
        if (k.Key == ConsoleKey.Enter)
        {
            break;
        }

        if (k.Key == ConsoleKey.Backspace)
        {
            if (sb.Length > 0)
            {
                sb.Length--;
            }
        }
        else if (!char.IsControl(k.KeyChar))
        {
            sb.Append(k.KeyChar);
        }
    }

    Console.Error.WriteLine();
    return sb.ToString();
}
