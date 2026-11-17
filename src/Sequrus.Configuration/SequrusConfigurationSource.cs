using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace Sequrus.Configuration;

internal sealed class SequrusConfigurationSource(IReadOnlyList<IConfigurationSource> inner, ISequrus? sequrus) : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        var innerBuilder = new ConfigurationBuilder();
        foreach (var (key, value) in builder.Properties)
        {
            innerBuilder.Properties[key] = value;
        }

        foreach (var source in inner)
        {
            innerBuilder.Add(source);
        }

        return new SequrusConfigurationProvider(innerBuilder.Build(), sequrus ?? Sq.Current);
    }
}

internal sealed class SequrusConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly IConfigurationRoot _inner;
    private readonly ISequrus _sequrus;
    private readonly IDisposable _reloadSubscription;

    public SequrusConfigurationProvider(IConfigurationRoot inner, ISequrus sequrus)
    {
        _inner = inner;
        _sequrus = sequrus;
        _reloadSubscription = ChangeToken.OnChange(_inner.GetReloadToken, () =>
        {
            try
            {
                Load();
            }
            catch (CryptographicException)
            {
                // A bad value in an edited file must not crash the watcher thread: keep the last good data.
                return;
            }

            OnReload();
        });
    }

    public override void Load()
    {
        var data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in _inner.AsEnumerable())
        {
            try
            {
                data[key] = value is null ? null : _sequrus.DecryptConnectionString(value);
            }
            catch (CryptographicException ex)
            {
                // The configuration key name is not secret; the value is never included.
                throw new CryptographicException($"Configuration value '{key}' cannot be decrypted.", ex);
            }
        }

        Data = data;
    }

    public void Dispose()
    {
        _reloadSubscription.Dispose();
        (_inner as IDisposable)?.Dispose();
    }
}
