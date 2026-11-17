# Sequrus

Encrypts and decrypts strings and connection-string secrets for .NET 8 and later.
Values are encrypted with AES-256-GCM; the key comes from the `SEQURUS_KEY` environment variable.

> **Status: early (`0.2.1`).** The API and the value format may change before `1.0.0`.
> Do not use it to protect production secrets until `1.0.0` is published.

| Package | Purpose |
|---|---|
| `Sequrus` | Core library: `SqEncrypt` / `SqDecrypt` extensions, `ISequrus`, key helpers |
| `Sequrus.Configuration` | Decrypts `sq1:` values in any `Microsoft.Extensions.Configuration` source |
| `Sequrus.Cli` | `sequrus` dotnet tool: key generation, encryption, decryption, key rotation |

## Quick start

```bash
dotnet tool install -g Sequrus.Cli
export SEQURUS_KEY=$(sequrus keygen)
sequrus encrypt          # prompts for the secret, prints sq1:...
```

```csharp
using Sequrus;

var token = "p@ssw0rd".SqEncrypt();            // sq1:...
var secret = token.SqDecrypt();                // p@ssw0rd
var conn = "Server=db;Password=sq1:AbC..."
    .SqDecryptConnectionString();              // Server=db;Password=p@ssw0rd
```

## Value format

```
sq1:<base64url( keyId[4] | nonce[12] | tag[16] | ciphertext )>
```

- `keyId` is the first 4 bytes of SHA-256 of the key; it selects the decryption key.
- The nonce is random, so the same input encrypts to a different value every time.
- The GCM tag authenticates the data; the prefix `sq1` and `keyId` are bound as associated data.
  Any modification makes decryption fail.

## Key

`SEQURUS_KEY` holds one base64 key of 32 bytes, or a comma-separated list: `newKey,oldKey`.
The first key encrypts; every key in the list can decrypt.

- `sequrus keygen` creates a random key.
- `sequrus keygen --password [--salt=SALT]` derives a key from a password with PBKDF2-SHA256
  (600 000 iterations). Keep the printed salt to derive the same key again; the salt is not secret.

The key list is read once, on first use, and cached for the process lifetime.
If the variable is missing, every call throws `InvalidOperationException` until it is set.

## API

| Extension (uses `Sq.Current`) | `ISequrus` method |
|---|---|
| `string.SqEncrypt()`, `byte[].SqEncrypt()` | `Encrypt(string)`, `Encrypt(ReadOnlySpan<byte>)` |
| `string.SqDecrypt()`, `SqDecryptBytes()` | `Decrypt`, `DecryptBytes` |
| `string.SqTryDecrypt(out string?)` | `TryDecrypt` |
| `string.SqDecryptConnectionString()` | `DecryptConnectionString` |
| `string.SqReencrypt()` | `Reencrypt` |
| `string.SqIsEncrypted()` | `SequrusCipher.IsEncrypted` (static) |

`Sq.Configure(ISequrus)` replaces the process-wide instance, e.g. in tests or with keys from another store.
For dependency injection, register `ISequrus` directly:

```csharp
services.AddSingleton<ISequrus>(SequrusCipher.FromEnvironment());
```

### Connection strings

`DecryptConnectionString` replaces every `sq1:` token in the text and keeps the rest unchanged,
so it works for any provider and for any number of encrypted values.
A token must not be preceded by a letter, digit, `-` or `_`.

The decrypted value is inserted as is. If a secret contains `;` or quotes, encrypt it already quoted
according to the provider's rules (for example `"p;ss"`).

## Configuration

```csharp
builder.Configuration.AddSequrus();   // call after the sources you want decrypted
```

Every `sq1:` token in the sources added before `AddSequrus()` is decrypted on build and on reload.
A value that cannot be decrypted throws `CryptographicException` at startup; the message names the
configuration key, never the value. If such a value appears on reload, the last good configuration is kept.
A plain value that happens to contain an `sq1:` token (for example a password starting with `sq1:`) is
treated as encrypted, so encrypt such values too.

## Key rotation

1. Generate a new key and set `SEQURUS_KEY=newKey,oldKey`.
2. Re-encrypt stored values: `sequrus reencrypt < appsettings.json > appsettings.new.json`
   (or `ISequrus.Reencrypt` in code).
3. Remove `oldKey` from the list when no value uses it.

## CLI

| Command | Description |
|---|---|
| `sequrus keygen` | Print a new random key |
| `sequrus keygen -p\|--password [-s\|--salt=SALT]` | Derive a key from a password |
| `sequrus encrypt` | Encrypt a secret with the first key |
| `sequrus decrypt` | Decrypt an `sq1:` value |
| `sequrus reencrypt` | Re-encrypt every `sq1:` token from stdin to stdout |
| `sequrus help [COMMAND]`, `sequrus COMMAND --help` | Show help |

Exit codes: `0` success, `1` error (wrong key, corrupted value, missing `SEQURUS_KEY`), `2` invalid options.
Command-line parsing uses [Optionus](https://www.nuget.org/packages/Optionus).

Secrets are never accepted as arguments, because arguments stay in shell history and process lists.
They are read from a hidden prompt, or from stdin when input is redirected.

## Build and test

```bash
dotnet build -c Release
dotnet test -c Release
```

Requires the .NET 10 SDK; the libraries target .NET 8.

## Versioning

The project follows [Semantic Versioning](https://semver.org/). Versions below `1.0.0` and versions
with a pre-release suffix (`-alpha`, `-beta`, `-rc`) may contain breaking changes.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but
not limited to the warranties of merchantability, fitness for a particular purpose and
non-infringement. In no event shall the author be liable for any claim, damages or other liability,
including loss of data or disclosure of secrets, arising from the use of this software.

The library has not been reviewed by an independent security auditor. You are responsible for
evaluating whether it meets your security requirements, for protecting the keys, and for keeping
backups of the keys: a value encrypted with a lost key cannot be recovered.

## License

MIT.
