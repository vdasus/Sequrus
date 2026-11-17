using System.Security.Cryptography;
using AutoFixture;
using FluentAssertions;
using Xunit;

namespace Sequrus.Tests;

public class SequrusCipherTests
{
    private static readonly string KeyA = SequrusKey.Generate();
    private static readonly string KeyB = SequrusKey.Generate();
    private readonly Fixture _fixture = new();

    [Theory]
    [Trait("Category", "Unit")]
    [Trait("Priority", "High")]
    [InlineData("")]
    [InlineData("teststring")]
    [InlineData("пароль 密码 🔑;\"'=")]
    public void Encrypt_ThenDecrypt_ReturnsOriginal(string plaintext)
    {
        var sut = new SequrusCipher(KeyA);

        var encrypted = sut.Encrypt(plaintext);

        encrypted.Should().StartWith(SequrusCipher.Prefix);
        if (plaintext.Length > 0)
        {
            encrypted.Should().NotContain(plaintext);
        }

        sut.Decrypt(encrypted).Should().Be(plaintext);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Encrypt_RandomString_RoundTrips()
    {
        var plaintext = _fixture.Create<string>();
        var sut = new SequrusCipher(KeyA);

        sut.Decrypt(sut.Encrypt(plaintext)).Should().Be(plaintext);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Encrypt_Bytes_RoundTrips()
    {
        var data = _fixture.CreateMany<byte>(100).ToArray();
        var sut = new SequrusCipher(KeyA);

        sut.DecryptBytes(sut.Encrypt(data)).Should().Equal(data);
    }

    [Fact]
    [Trait("Category", "Unit")]
    [Trait("Priority", "High")]
    public void Encrypt_SameInputTwice_ReturnsDifferentValues()
    {
        var sut = new SequrusCipher(KeyA);

        sut.Encrypt("same").Should().NotBe(sut.Encrypt("same"));
    }

    [Fact]
    [Trait("Category", "Security")]
    [Trait("Priority", "High")]
    public void Decrypt_TamperedValue_Throws()
    {
        var sut = new SequrusCipher(KeyA);
        var encrypted = sut.Encrypt("secret");
        var last = encrypted[^1];
        var tampered = encrypted[..^1] + (last == 'A' ? 'B' : 'A');

        sut.Invoking(s => s.Decrypt(tampered)).Should().Throw<CryptographicException>();
        sut.TryDecrypt(tampered, out var result).Should().BeFalse();
        result.Should().BeNull();
    }

    [Fact]
    [Trait("Category", "Security")]
    [Trait("Priority", "High")]
    public void Decrypt_WithOtherKey_Throws()
    {
        var encrypted = new SequrusCipher(KeyA).Encrypt("secret");

        new SequrusCipher(KeyB).Invoking(s => s.Decrypt(encrypted)).Should().Throw<CryptographicException>();
    }

    [Theory]
    [Trait("Category", "Unit")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("plain text")]
    [InlineData("sq1:")]
    [InlineData("sq1:@@@")]
    [InlineData("sq1:AAAA")]
    public void TryDecrypt_InvalidInput_ReturnsFalse(string? input)
    {
        new SequrusCipher(KeyA).TryDecrypt(input, out var result).Should().BeFalse();
        result.Should().BeNull();
    }

    [Fact]
    [Trait("Category", "Unit")]
    [Trait("Priority", "High")]
    public void Rotation_OldValueDecryptsAndReencryptUsesNewKey()
    {
        var oldValue = new SequrusCipher(KeyA).Encrypt("secret");
        var rotated = new SequrusCipher(KeyB, KeyA);

        var reencrypted = rotated.Reencrypt(oldValue);

        rotated.Decrypt(oldValue).Should().Be("secret");
        new SequrusCipher(KeyB).Decrypt(reencrypted).Should().Be("secret");
        new SequrusCipher(KeyA).TryDecrypt(reencrypted, out _).Should().BeFalse();
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Parse_CommaSeparatedList_FirstKeyEncrypts()
    {
        var sut = SequrusCipher.Parse($" {KeyB} , {KeyA} ");

        new SequrusCipher(KeyB).Decrypt(sut.Encrypt("x")).Should().Be("x");
    }

    [Theory]
    [Trait("Category", "Security")]
    [InlineData("not-base64!")]
    [InlineData("AAAA")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Constructor_InvalidKey_ThrowsWithoutEchoingKey(string badKey)
    {
        var act = () => new SequrusCipher(badKey);

        act.Should().Throw<ArgumentException>().Which.Message.Should().NotContain(badKey);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Constructor_NoKeys_Throws()
    {
        var act = () => SequrusCipher.Parse(" , ");

        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [Trait("Category", "Unit")]
    [InlineData("sq1:AbC-_9", true)]
    [InlineData("sq1:", false)]
    [InlineData("sq1:a b", false)]
    [InlineData("Password=sq1:abc", false)]
    [InlineData(null, false)]
    public void IsEncrypted_RecognisesWholeToken(string? value, bool expected)
    {
        SequrusCipher.IsEncrypted(value).Should().Be(expected);
    }
}
