using FluentAssertions;
using Xunit;

namespace Sequrus.Tests;

[CollectionDefinition(nameof(GlobalState), DisableParallelization = true)]
public sealed class GlobalState;

// Touches the process-wide Sq.Current and the SEQURUS_KEY variable, so it runs alone.
[Collection(nameof(GlobalState))]
public sealed class GlobalStateTests : IDisposable
{
    private readonly string? _savedEnv = Environment.GetEnvironmentVariable(SequrusCipher.EnvironmentVariable);

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(SequrusCipher.EnvironmentVariable, _savedEnv);
        Sq.Configure(null);
    }

    [Fact]
    [Trait("Category", "Unit")]
    [Trait("Priority", "High")]
    public void Extensions_UseKeyFromEnvironment()
    {
        var key = SequrusKey.Generate();
        Environment.SetEnvironmentVariable(SequrusCipher.EnvironmentVariable, key);
        Sq.Configure(null);

        var encrypted = "secret".SqEncrypt();

        new SequrusCipher(key).Decrypt(encrypted).Should().Be("secret");
        encrypted.SqDecrypt().Should().Be("secret");
        encrypted.SqIsEncrypted().Should().BeTrue();
        $"Password={encrypted}".SqDecryptConnectionString().Should().Be("Password=secret");
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void MissingVariable_ThrowsEachTime_ThenWorksOnceSet()
    {
        Environment.SetEnvironmentVariable(SequrusCipher.EnvironmentVariable, null);
        Sq.Configure(null);

        var act = () => "x".SqEncrypt();

        act.Should().Throw<InvalidOperationException>();
        act.Should().Throw<InvalidOperationException>();

        Environment.SetEnvironmentVariable(SequrusCipher.EnvironmentVariable, SequrusKey.Generate());
        "x".SqEncrypt().SqDecrypt().Should().Be("x");
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Configure_OverridesEnvironment()
    {
        Environment.SetEnvironmentVariable(SequrusCipher.EnvironmentVariable, SequrusKey.Generate());
        var configured = new SequrusCipher(SequrusKey.Generate());
        Sq.Configure(configured);

        configured.Decrypt("x".SqEncrypt()).Should().Be("x");
    }
}
