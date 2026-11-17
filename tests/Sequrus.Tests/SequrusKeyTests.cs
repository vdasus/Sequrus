using FluentAssertions;
using Xunit;

namespace Sequrus.Tests;

public class SequrusKeyTests
{
    [Fact]
    [Trait("Category", "Unit")]
    public void Generate_ReturnsDistinct32ByteKeys()
    {
        var a = SequrusKey.Generate();

        Convert.FromBase64String(a).Should().HaveCount(SequrusKey.KeySize);
        a.Should().NotBe(SequrusKey.Generate());
    }

    [Fact]
    [Trait("Category", "Unit")]
    [Trait("Priority", "High")]
    public void DeriveFromPassword_SameInput_SameKey_OtherSalt_OtherKey()
    {
        var salt = SequrusKey.GenerateSalt();

        var key = SequrusKey.DeriveFromPassword("pw", salt, 100_000);

        key.Should().Be(SequrusKey.DeriveFromPassword("pw", salt, 100_000));
        key.Should().NotBe(SequrusKey.DeriveFromPassword("pw", SequrusKey.GenerateSalt(), 100_000));
        new SequrusCipher(key).Decrypt(new SequrusCipher(key).Encrypt("x")).Should().Be("x");
    }

    [Fact]
    [Trait("Category", "Security")]
    public void DeriveFromPassword_ShortSaltOrFewIterations_Throws()
    {
        var shortSalt = () => SequrusKey.DeriveFromPassword("pw", new byte[8]);
        var fewIterations = () => SequrusKey.DeriveFromPassword("pw", SequrusKey.GenerateSalt(), 1000);

        shortSalt.Should().Throw<ArgumentException>();
        fewIterations.Should().Throw<ArgumentOutOfRangeException>();
    }
}
