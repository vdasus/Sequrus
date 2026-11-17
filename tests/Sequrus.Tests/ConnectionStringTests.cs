using FluentAssertions;
using Xunit;

namespace Sequrus.Tests;

public class ConnectionStringTests
{
    private readonly SequrusCipher _sut = new(SequrusKey.Generate());

    [Fact]
    [Trait("Category", "Unit")]
    [Trait("Priority", "High")]
    public void DecryptConnectionString_ReplacesEveryToken()
    {
        var input = $"Data Source = srv;User ID={_sut.Encrypt("user")};Password = {_sut.Encrypt("p@ss")} ";

        _sut.DecryptConnectionString(input).Should().Be("Data Source = srv;User ID=user;Password = p@ss ");
    }

    [Theory]
    [Trait("Category", "Unit")]
    [InlineData("")]
    [InlineData("Server=x;Password=plain")]
    [InlineData("Server=x;Password=xsq1:abc")]
    public void DecryptConnectionString_NoToken_ReturnsInputUnchanged(string input)
    {
        _sut.DecryptConnectionString(input).Should().Be(input);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void DecryptConnectionString_BadToken_Throws()
    {
        var act = () => _sut.DecryptConnectionString("Server=x;Password=sq1:AAAAAAAA");

        act.Should().Throw<System.Security.Cryptography.CryptographicException>();
    }
}
