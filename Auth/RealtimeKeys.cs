using System.Security.Cryptography;
using System.Text;

namespace ElevateRealtime.Auth;

/// <summary>Which credential authorized a /api/notify call.</summary>
public enum NotifyAuthorization
{
    Refused,
    ServerKey,
    LegacyPublicKey,
}

/// <summary>
/// Public browser key (hub only) + server-only notify key + transition switch.
/// See AGENTS.md §H-4a key split.
/// </summary>
public sealed class RealtimeKeys
{
    public const int MinServerKeyLength = 32;
    public const string PublicKeyVariable = "SIGNALR_API_KEY";
    public const string ServerKeyVariable = "SIGNALR_SERVER_KEY";
    public const string AcceptPublicKeyOnNotifyVariable = "SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY";

    private readonly byte[] _publicKeyHash;
    private readonly byte[]? _serverKeyHash;
    private int _serverKeyUsed;

    /// <summary>Keys are trimmed here and on every presented value, matching notify.ts.</summary>
    public RealtimeKeys(string publicKey, string? serverKey, bool acceptPublicKeyOnNotify)
    {
        publicKey = publicKey?.Trim() ?? "";
        serverKey = serverKey?.Trim();
        if (publicKey.Length == 0)
            throw new InvalidOperationException($"{PublicKeyVariable} is required");

        _publicKeyHash = Hash(publicKey);

        if (!string.IsNullOrEmpty(serverKey))
        {
            if (serverKey.Length < MinServerKeyLength)
                throw new InvalidOperationException(
                    $"{ServerKeyVariable} must be at least {MinServerKeyLength} characters");
            _serverKeyHash = Hash(serverKey);
            if (CryptographicOperations.FixedTimeEquals(_serverKeyHash, _publicKeyHash))
                throw new InvalidOperationException(
                    $"{ServerKeyVariable} must differ from {PublicKeyVariable} (the public browser key)");
        }

        AcceptsPublicKeyOnNotify = _serverKeyHash is null || acceptPublicKeyOnNotify;
    }

    public bool HasServerKey => _serverKeyHash is not null;

    /// <summary>True in legacy (no server key) and transition modes; false in the enforced end state.</summary>
    public bool AcceptsPublicKeyOnNotify { get; }

    public string Mode => !HasServerKey ? "legacy" : AcceptsPublicKeyOnNotify ? "transition" : "enforced";

    /// <summary>
    /// Server key and switch must agree: a key needs an explicit switch, and switch=false needs a key,
    /// so neither a lone key write nor a blanked key can change the mode silently.
    /// </summary>
    public static RealtimeKeys FromEnvironment(Func<string, string?> getVariable)
    {
        var publicKey = getVariable(PublicKeyVariable)
            ?? throw new InvalidOperationException($"{PublicKeyVariable} is required");
        var serverKey = getVariable(ServerKeyVariable);
        var hasServerKey = !string.IsNullOrWhiteSpace(serverKey);
        var acceptPublicKey = ParseSwitch(getVariable(AcceptPublicKeyOnNotifyVariable));
        if (hasServerKey && acceptPublicKey is null)
            throw new InvalidOperationException(
                $"{AcceptPublicKeyOnNotifyVariable} must be set explicitly (true = transition, false = enforced) " +
                $"when {ServerKeyVariable} is set");
        // Fail closed: enforced was requested, so a blank key must not degrade to legacy.
        if (!hasServerKey && acceptPublicKey == false)
            throw new InvalidOperationException(
                $"{AcceptPublicKeyOnNotifyVariable}=false requires {ServerKeyVariable}");
        return new RealtimeKeys(publicKey, hasServerKey ? serverKey : null, acceptPublicKey ?? false);
    }

    /// <summary>Hub connections: the public browser key only; the server key never opens a browser session.</summary>
    public bool IsPublicKey(string? presented)
    {
        presented = presented?.Trim();
        return !string.IsNullOrEmpty(presented)
               && CryptographicOperations.FixedTimeEquals(Hash(presented), _publicKeyHash);
    }

    public NotifyAuthorization AuthorizeNotify(string? presented)
    {
        presented = presented?.Trim();
        if (string.IsNullOrEmpty(presented))
            return NotifyAuthorization.Refused;

        var presentedHash = Hash(presented);
        var isServer = _serverKeyHash is not null
                       && CryptographicOperations.FixedTimeEquals(presentedHash, _serverKeyHash);
        var isPublic = CryptographicOperations.FixedTimeEquals(presentedHash, _publicKeyHash);

        if (isServer) return NotifyAuthorization.ServerKey;
        if (isPublic && AcceptsPublicKeyOnNotify) return NotifyAuthorization.LegacyPublicKey;
        return NotifyAuthorization.Refused;
    }

    /// <summary>True exactly once per process: the first notify authorized by the server key.</summary>
    public bool TryMarkFirstServerKeyUse() => Interlocked.Exchange(ref _serverKeyUsed, 1) == 0;

    private static bool? ParseSwitch(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        null or "" => null,
        "false" or "0" => false,
        "true" or "1" => true,
        _ => throw new InvalidOperationException(
            $"{AcceptPublicKeyOnNotifyVariable} must be true/false/1/0, got an unrecognized value"),
    };

    // Hash-then-compare so FixedTimeEquals sees equal-length inputs and does not leak key length.
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
}
