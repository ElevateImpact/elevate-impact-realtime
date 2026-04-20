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
        // Try query parameter first, then header
        var apiKey = Request.Query["apiKey"].FirstOrDefault()
                     ?? Request.Headers["X-Api-Key"].FirstOrDefault();

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
