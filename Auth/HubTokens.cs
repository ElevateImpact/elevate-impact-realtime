using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ElevateRealtime.Auth;

/// <summary>Outcome of verifying a hub token; UserId/ExpiresAt are set only on success.</summary>
public readonly record struct HubTokenResult(
    bool Succeeded, string? UserId, string? Failure, long ExpiresAt = 0, bool ViaPreviousKey = false)
{
    public static HubTokenResult Fail(string reason) => new(false, null, reason);
}

/// <summary>
/// HMAC-SHA256 hub identity token: base64url(canonical JSON {sub,aud,iat,exp}).base64url(HMAC(key, payload segment)).
/// No header, no algorithm field. Minted by the rewrite (hubToken.ts). See AGENTS.md §H-14.
/// </summary>
public sealed class HubTokens
{
    public const string Audience = "realtime-hub";
    public const int MaxLifetimeSeconds = 900;
    public const int ClockSkewSeconds = 60;
    public const int MaxTokenLength = 2048;
    public const int MaxSubjectLength = 256;

    private static readonly string[] RequiredFields = { "sub", "aud", "iat", "exp" };
    private readonly byte[] _key;
    private readonly byte[]? _previousKey;

    /// <param name="previousKey">Rotation only: tokens signed with it still verify. See AGENTS.md §H-14 rotation.</param>
    public HubTokens(string key, string? previousKey = null)
    {
        key = key?.Trim() ?? "";
        if (key.Length == 0) throw new InvalidOperationException("hub token key is required");
        _key = Encoding.UTF8.GetBytes(key);
        previousKey = previousKey?.Trim();
        if (!string.IsNullOrEmpty(previousKey)) _previousKey = Encoding.UTF8.GetBytes(previousKey);
    }

    public bool HasPreviousKey => _previousKey is not null;

    /// <summary>Signs a payload exactly as given (tests and shared vectors; production minting is web-side).</summary>
    public static string Sign(string key, string payloadJson)
    {
        var payload = EncodeBase64Url(Encoding.UTF8.GetBytes(payloadJson));
        var signature = HMACSHA256.HashData(Encoding.UTF8.GetBytes(key.Trim()), Encoding.ASCII.GetBytes(payload));
        return $"{payload}.{EncodeBase64Url(signature)}";
    }

    public HubTokenResult Verify(string? token, DateTimeOffset now)
    {
        token = token?.Trim();
        if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength)
            return HubTokenResult.Fail("malformed");

        var parts = token.Split('.');
        if (parts.Length != 2) return HubTokenResult.Fail("malformed");

        var signature = DecodeBase64Url(parts[1]);
        var payloadBytes = DecodeBase64Url(parts[0]);
        if (signature is null || payloadBytes is null) return HubTokenResult.Fail("malformed");

        // Signature before parsing: nothing unauthenticated reaches the JSON reader.
        var signedBytes = Encoding.ASCII.GetBytes(parts[0]);
        var viaPreviousKey = false;
        if (!CryptographicOperations.FixedTimeEquals(signature, HMACSHA256.HashData(_key, signedBytes)))
        {
            if (_previousKey is null
                || !CryptographicOperations.FixedTimeEquals(signature, HMACSHA256.HashData(_previousKey, signedBytes)))
                return HubTokenResult.Fail("bad-signature");
            viaPreviousKey = true;
        }

        string sub;
        long iat, exp;
        try
        {
            using var document = JsonDocument.Parse(payloadBytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return HubTokenResult.Fail("malformed");

            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!seen.Add(property.Name) || Array.IndexOf(RequiredFields, property.Name) < 0)
                    return HubTokenResult.Fail("malformed");
            if (seen.Count != RequiredFields.Length) return HubTokenResult.Fail("malformed");

            var subElement = root.GetProperty("sub");
            var audElement = root.GetProperty("aud");
            if (subElement.ValueKind != JsonValueKind.String || audElement.ValueKind != JsonValueKind.String
                || !root.GetProperty("iat").TryGetInt64(out iat) || !root.GetProperty("exp").TryGetInt64(out exp))
                return HubTokenResult.Fail("malformed");

            if (audElement.GetString() != Audience) return HubTokenResult.Fail("wrong-audience");
            sub = subElement.GetString() ?? "";
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            return HubTokenResult.Fail("malformed");
        }

        if (sub.Length == 0 || sub.Length > MaxSubjectLength) return HubTokenResult.Fail("malformed");

        // The verifier, not only the minter, bounds the lifetime.
        var lifetime = exp - iat;
        if (lifetime <= 0 || lifetime > MaxLifetimeSeconds) return HubTokenResult.Fail("lifetime");

        var nowSeconds = now.ToUnixTimeSeconds();
        if (iat > nowSeconds + ClockSkewSeconds) return HubTokenResult.Fail("not-yet-valid");
        if (nowSeconds > exp + ClockSkewSeconds) return HubTokenResult.Fail("expired");

        return new HubTokenResult(true, sub, null, exp, viaPreviousKey);
    }

    private static string EncodeBase64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Strict: url alphabet only, no padding, canonical trailing bits (one token has one spelling).</summary>
    private static byte[]? DecodeBase64Url(string value)
    {
        if (value.Length == 0 || value.Length % 4 == 1) return null;
        foreach (var c in value)
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
                return null;

        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        byte[] bytes;
        try { bytes = Convert.FromBase64String(base64); }
        catch (FormatException) { return null; }
        return EncodeBase64Url(bytes) == value ? bytes : null;
    }
}
