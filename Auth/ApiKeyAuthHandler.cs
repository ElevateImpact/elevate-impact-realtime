using System.Security.Claims;
using System.Text.Encodings.Web;
using ElevateRealtime.Hubs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace ElevateRealtime.Auth;

/// <summary>Hub auth: a verified hub token, or (legacy/transition only) the public key + self-asserted ?userId=. See AGENTS.md §H-14.</summary>
public class ApiKeyAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly RealtimeKeys _keys;
    private readonly HubIdentityKeys _identity;

    public ApiKeyAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        RealtimeKeys keys,
        HubIdentityKeys identity)
        : base(options, logger, encoder)
    {
        _keys = keys;
        _identity = identity;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // The notify endpoint is authorized by NotifyAuth, not here; skip only on its routed metadata (a null endpoint is judged). See AGENTS.md §notify-auth-noise.
        if (Context.GetEndpoint()?.Metadata.GetMetadata<NotifyEndpointMarker>() is not null)
            return Task.FromResult(AuthenticateResult.NoResult());

        // Preferred: Authorization: Bearer <key> (SignalR JS client's
        // accessTokenFactory routes through this header). Fall back to the
        // legacy X-Api-Key header and ?apiKey= query param for older clients.
        var authHeader = Request.Headers["Authorization"].FirstOrDefault();
        string? apiKey = null;
        if (!string.IsNullOrEmpty(authHeader) &&
            authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            apiKey = authHeader.Substring("Bearer ".Length).Trim();
        }

        // `access_token` is NOT optional to support. WebSockets and
        // Server-Sent Events cannot set request headers, so for those two
        // transports the SignalR JS client puts accessTokenFactory's value in
        // the query string under exactly this name. Only the negotiate POST can
        // send the Bearer header.
        //
        // Without it the handshake half-works in a way that is hard to read:
        // negotiate returns 200, then every transport 401s, and the client
        // surfaces the generic "connection could not be found on the server …
        // check that sticky sessions are enabled" — which sends you looking for
        // a scaling problem that isn't there (the hub runs a single replica).
        apiKey ??= Request.Headers["X-Api-Key"].FirstOrDefault()
                   ?? Request.Query["access_token"].FirstOrDefault()
                   ?? Request.Query["apiKey"].FirstOrDefault();

        if (string.IsNullOrEmpty(apiKey))
            return Task.FromResult(AuthenticateResult.Fail("API key is required"));

        // Same credential slot carries either the public key (legacy wire) or a hub token (H-14 wire).
        if (_keys.IsPublicKey(apiKey))
        {
            if (!_identity.AcceptsAssertedUserId)
                return Task.FromResult(Refuse("public-key", "hub token required"));
            // Self-asserted: anyone with the public key can claim any userId. Closed by enforced mode (AGENTS.md §H-14).
            return Task.FromResult(Success(Request.Query["userId"].FirstOrDefault(),
                HubIdentityKeys.MethodAssertedUserId));
        }

        if (_identity.Tokens is { } tokens)
        {
            var verified = tokens.Verify(apiKey, DateTimeOffset.UtcNow);
            // Identity comes from the token only; ?userId= is ignored on this path.
            // The ticket expires with the token, so CloseOnAuthenticationExpiration ends the connection then (HubEndpoint).
            if (verified.Succeeded)
                return Task.FromResult(Success(verified.UserId,
                    verified.ViaPreviousKey ? HubIdentityKeys.MethodHubTokenPreviousKey : HubIdentityKeys.MethodHubToken,
                    DateTimeOffset.FromUnixTimeSeconds(verified.ExpiresAt)));
            if (LooksLikeToken(apiKey))
                return Task.FromResult(Refuse("invalid-token", verified.Failure!));
        }

        return Task.FromResult(Refuse("unknown", "Invalid API key"));
    }

    /// <summary>A null <paramref name="expiresUtc"/> (asserted path) leaves the connection unbounded, as before H-14.</summary>
    private AuthenticateResult Success(string? userId, string method, DateTimeOffset? expiresUtc = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Authentication, "ApiKey"),
            new(ClaimTypes.AuthenticationMethod, method),
        };
        if (!string.IsNullOrEmpty(userId))
            claims.Add(new Claim("userId", userId));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
        var properties = new AuthenticationProperties { ExpiresUtc = expiresUtc };
        return AuthenticateResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name));
    }

    private AuthenticateResult Refuse(string credentialKind, string reason)
    {
        Logger.LogWarning("Hub connect refused (mode {Mode}, credential {Credential}, reason {Reason})",
            _identity.Mode, credentialKind, reason);
        return AuthenticateResult.Fail(reason);
    }

    private static bool LooksLikeToken(string credential) => credential.Count(c => c == '.') == 1;
}
