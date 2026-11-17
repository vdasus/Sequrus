using System.Diagnostics;
using FluentAssertions;
using Xunit;

namespace Sequrus.Tests;

// Runs the real sequrus tool (Sequrus.Cli.dll, copied next to the tests) with redirected stdin.
public sealed class CliTests
{
    private readonly string _key = SequrusKey.Generate();

    [Fact]
    [Trait("Category", "Integration")]
    [Trait("Priority", "High")]
    public async Task EncryptThenDecrypt_ViaStdin_DropsOnlyOneTrailingLineBreak()
    {
        var encrypted = await Run("line1\nline2\n\n", "encrypt");
        encrypted.ExitCode.Should().Be(0, encrypted.Error);

        var decrypted = await Run(encrypted.Output, "decrypt");

        decrypted.ExitCode.Should().Be(0, decrypted.Error);
        // The secret keeps its own line break; WriteLine adds one more.
        decrypted.Output.Should().Be("line1\nline2\n" + Environment.NewLine);
    }

    [Fact]
    [Trait("Category", "Integration")]
    [Trait("Priority", "High")]
    public async Task Decrypt_UndecryptableValue_ExitsWithOne()
    {
        var result = await Run("sq1:AAAA", "decrypt");

        result.ExitCode.Should().Be(1);
        result.Output.Should().BeEmpty();
        result.Error.Should().StartWith("error:");
    }

    [Fact]
    [Trait("Category", "Integration")]
    [Trait("Priority", "High")]
    public async Task Encrypt_SecretAsArgument_ExitsWithTwoWithoutEchoingIt()
    {
        var result = await Run("", "encrypt", "hunter2");

        result.ExitCode.Should().Be(2);
        result.Output.Should().BeEmpty();
        result.Error.Should().NotContain("hunter2");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task Reencrypt_RewritesTokensWithFirstKeyAndKeepsText()
    {
        var oldKey = SequrusKey.Generate();
        var token = new SequrusCipher(oldKey).Encrypt("secret");

        var result = await Run($"{{\"Db\": \"Password={token}\"}}", "reencrypt", keyList: $"{_key},{oldKey}");

        result.ExitCode.Should().Be(0, result.Error);
        result.Output.Should().NotContain(token);
        new SequrusCipher(_key).DecryptConnectionString(result.Output).Should().Be("{\"Db\": \"Password=secret\"}");
    }

    private async Task<(int ExitCode, string Output, string Error)> Run(string stdin, string command, string? argument = null, string? keyList = null)
    {
        var psi = new ProcessStartInfo("dotnet")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        // The copy next to the tests sits with net10.0 dependencies (Optionus), so it must not run on an older installed runtime.
        foreach (var arg in new[] { "exec", "--roll-forward", "LatestMajor", Path.Combine(AppContext.BaseDirectory, "Sequrus.Cli.dll") })
        {
            psi.ArgumentList.Add(arg);
        }
        psi.ArgumentList.Add(command);
        if (argument is not null)
        {
            psi.ArgumentList.Add(argument);
        }

        psi.Environment[SequrusCipher.ENVIRONMENT_VARIABLE] = keyList ?? _key;

        using var process = Process.Start(psi)!;
        process.StandardInput.Write(stdin);
        process.StandardInput.Close();
        var ct = TestContext.Current.CancellationToken;
        var output = process.StandardOutput.ReadToEndAsync(ct);
        var error = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        return (process.ExitCode, await output, await error);
    }
}
