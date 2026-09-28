namespace ElevateRealtime.Auth;

/// <summary>X-Api-Key gate for POST /api/notify. See AGENTS.md §H-4a key split.</summary>
public static class NotifyAuth
{
    public const string HeaderName = "X-Api-Key";

    /// <summary>Operators grep for this token to decide when the transition can close.</summary>
    public const string LegacyWarningToken = "H4_LEGACY_NOTIFY_KEY";

    /// <summary>Logged once per process: proves the web service is sending SIGNALR_SERVER_KEY.</summary>
    public const string ServerKeyFirstUseToken = "H4_SERVER_KEY_NOTIFY_OK";

    public static bool IsAuthorized(HttpRequest request, RealtimeKeys keys, ILogger logger)
    {
        var presented = request.Headers[HeaderName].FirstOrDefault();
        switch (keys.AuthorizeNotify(presented))
        {
            case NotifyAuthorization.ServerKey:
                if (keys.TryMarkFirstServerKeyUse())
                    logger.LogInformation("{Token}: first /api/notify authorized with SIGNALR_SERVER_KEY (mode {Mode})",
                        ServerKeyFirstUseToken, keys.Mode);
                return true;
            case NotifyAuthorization.LegacyPublicKey:
                logger.LogWarning(
                    "{Token}: /api/notify authorized with the PUBLIC browser key (mode {Mode}). " +
                    "Set SIGNALR_SERVER_KEY on the web service; close with SIGNALR_NOTIFY_ACCEPT_PUBLIC_KEY=false once this stops appearing",
                    LegacyWarningToken, keys.Mode);
                return true;
            default:
                logger.LogWarning(
                    "/api/notify refused (mode {Mode}, credential {Credential})",
                    keys.Mode,
                    string.IsNullOrEmpty(presented) ? "missing"
                        : keys.IsPublicKey(presented) ? "public-key" : "unknown");
                return false;
        }
    }
}
