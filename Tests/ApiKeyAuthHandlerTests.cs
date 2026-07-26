using System.Text.Encodings.Web;
using ElevateRealtime.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ElevateRealtime.Tests;

/// <summary>
/// Auth surface for the hub. The transport-specific cases matter more than they
/// look: WebSockets and Server-Sent Events cannot set request headers, so the
/// SignalR JS client passes accessTokenFactory's value as the `access_token`
/// query parameter. Missing that made negotiate succeed and every transport
/// 401, which surfaces as a misleading "sticky sessions" error.
/// </summary>
public class ApiKeyAuthHandlerTests
{
    private const string Key = "test-key-value";

    private static async Task<AuthenticateResult> AuthenticateAsync(
        Action<HttpContext> configure)
    {
        var handler = new ApiKeyAuthHandler(
            new OptionsMonitorStub(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            new ApiKeyConfig(Key));

        var context = new DefaultHttpContext();
        configure(context);

        await handler.InitializeAsync(
            new AuthenticationScheme("ApiKey", null, typeof(ApiKeyAuthHandler)),
            context);

        return await handler.AuthenticateAsync();
    }

    [Fact]
    public async Task BearerHeader_Authenticates()
    {
        var result = await AuthenticateAsync(
            ctx => ctx.Request.Headers["Authorization"] = $"Bearer {Key}");
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task XApiKeyHeader_Authenticates()
    {
        var result = await AuthenticateAsync(ctx => ctx.Request.Headers["X-Api-Key"] = Key);
        Assert.True(result.Succeeded);
    }

    /// <summary>
    /// The regression this file exists for. WebSockets and SSE arrive with the
    /// key ONLY in `access_token`.
    /// </summary>
    [Fact]
    public async Task AccessTokenQueryParam_Authenticates()
    {
        var result = await AuthenticateAsync(
            ctx => ctx.Request.QueryString = new QueryString($"?access_token={Key}"));
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task LegacyApiKeyQueryParam_StillAuthenticates()
    {
        var result = await AuthenticateAsync(
            ctx => ctx.Request.QueryString = new QueryString($"?apiKey={Key}"));
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task WrongKey_IsRejected_OnEveryCarrier()
    {
        Assert.False((await AuthenticateAsync(
            ctx => ctx.Request.Headers["Authorization"] = "Bearer nope")).Succeeded);
        Assert.False((await AuthenticateAsync(
            ctx => ctx.Request.Headers["X-Api-Key"] = "nope")).Succeeded);
        Assert.False((await AuthenticateAsync(
            ctx => ctx.Request.QueryString = new QueryString("?access_token=nope"))).Succeeded);
    }

    [Fact]
    public async Task NoCredential_IsRejected()
        => Assert.False((await AuthenticateAsync(_ => { })).Succeeded);

    /// <summary>
    /// userId rides the query string on every transport, so a token supplied via
    /// access_token must still yield the userId claim the hub groups on.
    /// </summary>
    [Fact]
    public async Task AccessTokenTransport_StillCarriesUserIdClaim()
    {
        var result = await AuthenticateAsync(
            ctx => ctx.Request.QueryString = new QueryString($"?access_token={Key}&userId=user-123"));

        Assert.True(result.Succeeded);
        Assert.Equal("user-123", result.Principal!.FindFirst("userId")?.Value);
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<AuthenticationSchemeOptions>
    {
        public AuthenticationSchemeOptions CurrentValue { get; } = new();
        public AuthenticationSchemeOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<AuthenticationSchemeOptions, string?> listener) => null;
    }
}
