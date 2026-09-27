using System.Security.Claims;

namespace ElevateRealtime.Auth;

/// <summary>
/// Hub identity mode: legacy (asserted ?userId=), transition (token or asserted), enforced (token only).
/// See AGENTS.md §H-14 hub identity.
/// </summary>
public sealed class HubIdentityKeys
{
    public const int MinTokenKeyLength = 32;
    public const string TokenKeyVariable = "SIGNALR_HUB_TOKEN_KEY";
    public const string AcceptAssertedUserIdVariable = "SIGNALR_HUB_ACCEPT_ASSERTED_USERID";
    /// <summary>Rotation only: the outgoing key, still accepted for verification. See AGENTS.md §H-14 rotation.</summary>
    public const string PreviousTokenKeyVariable = "SIGNALR_HUB_TOKEN_KEY_PREVIOUS";

    /// <summary>Boot line: the running process's hub identity mode.</summary>
    public const string ModeLogToken = "H14_HUB_IDENTITY_MODE";
    /// <summary>Per connection authenticated by the public key + self-asserted ?userId=.</summary>
    public const string LegacyIdentityToken = "H14_LEGACY_HUB_IDENTITY";
    /// <summary>Once per process: the first connection authenticated by a verified hub token.</summary>
    public const string TokenFirstUseToken = "H14_HUB_TOKEN_OK";
    /// <summary>Per connection authenticated by a token signed with the previous key (rotation tail).</summary>
    public const string PreviousKeyToken = "H14_HUB_TOKEN_PREVIOUS_KEY";

    /// <summary>ClaimTypes.AuthenticationMethod values set by ApiKeyAuthHandler.</summary>
    public const string MethodHubToken = "hub-token";
    public const string MethodHubTokenPreviousKey = "hub-token-previous-key";
    public const string MethodAssertedUserId = "asserted-userid";

    private int _tokenUsed;

    public HubIdentityKeys(string? tokenKey, bool acceptAssertedUserId, RealtimeKeys keys, string? previousTokenKey = null)
    {
        tokenKey = tokenKey?.Trim();
        previousTokenKey = previousTokenKey?.Trim();
        if (!string.IsNullOrEmpty(previousTokenKey) && string.IsNullOrEmpty(tokenKey))
            throw new InvalidOperationException($"{PreviousTokenKeyVariable} requires {TokenKeyVariable}");
        if (!string.IsNullOrEmpty(tokenKey))
        {
            RequireDistinctKey(TokenKeyVariable, tokenKey, keys);
            if (!string.IsNullOrEmpty(previousTokenKey))
            {
                RequireDistinctKey(PreviousTokenKeyVariable, previousTokenKey, keys);
                if (previousTokenKey == tokenKey)
                    throw new InvalidOperationException($"{PreviousTokenKeyVariable} must differ from {TokenKeyVariable}");
            }
            Tokens = new HubTokens(tokenKey, previousTokenKey);
        }

        AcceptsAssertedUserId = Tokens is null || acceptAssertedUserId;
    }

    /// <summary>Null in legacy mode: no key, so no token can be verified.</summary>
    public HubTokens? Tokens { get; }

    /// <summary>True in legacy and transition; false in enforced (the public key alone cannot connect).</summary>
    public bool AcceptsAssertedUserId { get; }

    public string Mode => Tokens is null ? "legacy" : AcceptsAssertedUserId ? "transition" : "enforced";

    /// <summary>True while SIGNALR_HUB_TOKEN_KEY_PREVIOUS is set (a key rotation is in progress).</summary>
    public bool RotationInProgress => Tokens?.HasPreviousKey == true;

    /// <summary>Key and switch must agree, mirroring RealtimeKeys.FromEnvironment.</summary>
    public static HubIdentityKeys FromEnvironment(Func<string, string?> getVariable, RealtimeKeys keys)
    {
        var tokenKey = getVariable(TokenKeyVariable);
        var hasTokenKey = !string.IsNullOrWhiteSpace(tokenKey);
        var acceptAsserted = ParseSwitch(getVariable(AcceptAssertedUserIdVariable));
        if (hasTokenKey && acceptAsserted is null)
            throw new InvalidOperationException(
                $"{AcceptAssertedUserIdVariable} must be set explicitly (true = transition, false = enforced) " +
                $"when {TokenKeyVariable} is set");
        // Fail closed: enforced was requested, so a blank key must not degrade to legacy.
        if (!hasTokenKey && acceptAsserted == false)
            throw new InvalidOperationException($"{AcceptAssertedUserIdVariable}=false requires {TokenKeyVariable}");
        return new HubIdentityKeys(hasTokenKey ? tokenKey : null, acceptAsserted ?? false, keys,
            getVariable(PreviousTokenKeyVariable));
    }

    private static void RequireDistinctKey(string variable, string key, RealtimeKeys keys)
    {
        if (key.Length < MinTokenKeyLength)
            throw new InvalidOperationException($"{variable} must be at least {MinTokenKeyLength} characters");
        if (keys.MatchesPublicOrServerKey(key))
            throw new InvalidOperationException(
                $"{variable} must differ from {RealtimeKeys.PublicKeyVariable} (the public browser key) " +
                $"and from {RealtimeKeys.ServerKeyVariable}");
    }

    /// <summary>True exactly once per process.</summary>
    public bool TryMarkFirstTokenUse() => Interlocked.Exchange(ref _tokenUsed, 1) == 0;

    /// <summary>Called once per hub connection: warns on asserted identity, proves token use once.</summary>
    public void LogConnection(ClaimsPrincipal? user, ILogger logger)
    {
        var method = user?.FindFirst(ClaimTypes.AuthenticationMethod)?.Value;
        var userId = user?.FindFirst("userId")?.Value;
        if (method == MethodAssertedUserId)
            logger.LogWarning(
                "{Token}: hub connection identified by self-asserted ?userId={UserId} (mode {Mode}). " +
                "Set SIGNALR_HUB_TOKEN_KEY on web; close with SIGNALR_HUB_ACCEPT_ASSERTED_USERID=false once this stops appearing",
                LegacyIdentityToken, userId, Mode);
        else if (method == MethodHubTokenPreviousKey)
            logger.LogWarning(
                "{Token}: hub connection for {UserId} verified by {Variable} (rotation tail). " +
                "Delete {Variable} once this stops appearing",
                PreviousKeyToken, userId, PreviousTokenKeyVariable, PreviousTokenKeyVariable);
        else if (method == MethodHubToken && TryMarkFirstTokenUse())
            logger.LogInformation("{Token}: first hub connection authenticated by a verified hub token (mode {Mode})",
                TokenFirstUseToken, Mode);
    }

    private static bool? ParseSwitch(string? raw) => raw?.Trim().ToLowerInvariant() switch
    {
        null or "" => null,
        "false" or "0" => false,
        "true" or "1" => true,
        _ => throw new InvalidOperationException(
            $"{AcceptAssertedUserIdVariable} must be true/false/1/0, got an unrecognized value"),
    };
}
