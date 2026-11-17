using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Sequrus.Configuration;
using Xunit;

namespace Sequrus.Tests;

public class ConfigurationTests
{
    private readonly SequrusCipher _cipher = new(SequrusKey.Generate());

    [Fact]
    [Trait("Category", "Integration")]
    [Trait("Priority", "High")]
    public void AddSequrus_DecryptsValuesAndEmbeddedTokens()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ApiKey"] = _cipher.Encrypt("k-123"),
                ["ConnectionStrings:Db"] = $"Server=x;Password={_cipher.Encrypt("p@ss")}",
                ["Plain"] = "as is",
            })
            .AddSequrus(_cipher)
            .Build();

        config["ApiKey"].Should().Be("k-123");
        config.GetConnectionString("Db").Should().Be("Server=x;Password=p@ss");
        config["Plain"].Should().Be("as is");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public void AddSequrus_SourceAddedAfter_IsNotDecrypted()
    {
        var token = _cipher.Encrypt("v");
        var config = new ConfigurationBuilder()
            .AddSequrus(_cipher)
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Late"] = token })
            .Build();

        config["Late"].Should().Be(token);
    }

    [Fact]
    [Trait("Category", "Integration")]
    public void AddSequrus_UndecryptableValue_FailsOnBuild()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Bad"] = new SequrusCipher(SequrusKey.Generate()).Encrypt("v") })
            .AddSequrus(_cipher);

        builder.Invoking(b => b.Build()).Should().Throw<CryptographicException>()
            .Which.Message.Should().Contain("'Bad'");
    }

    [Fact]
    [Trait("Category", "Integration")]
    [Trait("Priority", "High")]
    public void AddSequrus_OnConfigurationManager_DecryptsEarlierSources()
    {
        // ConfigurationManager is what WebApplicationBuilder.Configuration uses.
        using var manager = new ConfigurationManager();
        manager.AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = _cipher.Encrypt("v") });

        manager.AddSequrus(_cipher);

        manager["Key"].Should().Be("v");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public void Reload_DecryptsNewValue_AndKeepsLastGoodDataOnBadValue()
    {
        var source = new ReloadableSource();
        var config = new ConfigurationBuilder().Add(source).AddSequrus(_cipher).Build();

        source.Provider.Change("Key", _cipher.Encrypt("v1"));
        config["Key"].Should().Be("v1");

        var act = () => source.Provider.Change("Key", "sq1:AAAAAAAA");

        act.Should().NotThrow();
        config["Key"].Should().Be("v1");
    }

    private sealed class ReloadableSource : IConfigurationSource
    {
        public ReloadableProvider Provider { get; } = new();

        public IConfigurationProvider Build(IConfigurationBuilder builder) => Provider;
    }

    private sealed class ReloadableProvider : ConfigurationProvider
    {
        public void Change(string key, string value)
        {
            Set(key, value);
            OnReload();
        }
    }
}
