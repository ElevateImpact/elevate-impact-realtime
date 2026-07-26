using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace ElevateRealtime.Auth;

public record ApiKeyConfig(string Key);

public class ApiKeyAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ApiKeyConfig _apiKeyConfig;

    public ApiKeyAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ApiKeyConfig apiKeyConfig)
        : base(options, logger, encoder)
    {
        _apiKeyConfig = apiKeyConfig;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Preferred: Authorization: Bearer <key> (SignalR JS client's
        // accessTokenFactory routes through this header). Fall back to the
        // legacy X-Api-Key header and ?apiKey= query param so staggered
        // deploys + the server-to-server /api/notify path keep working.
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

        if (apiKey != _apiKeyConfig.Key)
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key"));

        var userId = Request.Query["userId"].FirstOrDefault();

        var claims = new List<Claim>
        {
            new(ClaimTypes.Authentication, "ApiKey"),
        };

        if (!string.IsNullOrEmpty(userId))
            claims.Add(new Claim("userId", userId));

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
