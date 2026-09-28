using System.Text.Encodings.Web;
using ElevateRealtime.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
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
    private const string ServerKey = "server-only-key-0123456789abcdefghijklmnop";

    private static Task<AuthenticateResult> AuthenticateAsync(Action<HttpContext> configure)
        => AuthenticateAsync(configure, new RealtimeKeys(Key, null, false));

    private static async Task<AuthenticateResult> AuthenticateAsync(
        Action<HttpContext> configure, RealtimeKeys keys)
    {
        var handler = new ApiKeyAuthHandler(
            new OptionsMonitorStub(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            keys,
            new HubIdentityKeys(null, false, keys));

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

    /// <summary>H-4 end state: the public key still opens the hub (browsers keep working).</summary>
    [Fact]
    public async Task PublicKey_ConnectsToHub_InEnforcedMode()
    {
        var result = await AuthenticateAsync(
            ctx => ctx.Request.QueryString = new QueryString($"?access_token={Key}&userId=u1"),
            new RealtimeKeys(Key, ServerKey, acceptPublicKeyOnNotify: false));
        Assert.True(result.Succeeded);
    }

    /// <summary>H-4: the server key is a notify credential, never a hub credential, on any carrier or mode.</summary>
    [Theory]
    [InlineData("bearer", true)]
    [InlineData("x-api-key", true)]
    [InlineData("access_token", true)]
    [InlineData("apiKey", true)]
    [InlineData("bearer", false)]
    [InlineData("x-api-key", false)]
    [InlineData("access_token", false)]
    [InlineData("apiKey", false)]
    public async Task ServerKey_IsRefusedOnHub(string carrier, bool acceptPublicKeyOnNotify)
    {
        var keys = new RealtimeKeys(Key, ServerKey, acceptPublicKeyOnNotify);
        var result = await AuthenticateAsync(ctx => Present(ctx, carrier, ServerKey), keys);
        Assert.False(result.Succeeded);
    }

    /// <summary>Control for the theory above: the same carriers accept the public key.</summary>
    [Theory]
    [InlineData("bearer")]
    [InlineData("x-api-key")]
    [InlineData("access_token")]
    [InlineData("apiKey")]
    public async Task PublicKey_IsAcceptedOnHub_OnEveryCarrier_InEnforcedMode(string carrier)
    {
        var keys = new RealtimeKeys(Key, ServerKey, acceptPublicKeyOnNotify: false);
        var result = await AuthenticateAsync(ctx => Present(ctx, carrier, Key), keys);
        Assert.True(result.Succeeded);
    }

    // ---- /api/notify belongs to NotifyAuth (AGENTS.md §notify-auth-noise) ----

    private const string HubKey = "hub-token-key-0123456789abcdefghijklmnopqr";

    private static async Task<(AuthenticateResult result, CapturingLoggerProvider log)> AuthenticateLogged(
        string path, HubIdentityKeys identity, RealtimeKeys keys, Action<HttpContext> configure)
    {
        var log = new CapturingLoggerProvider();
        var handler = new ApiKeyAuthHandler(new OptionsMonitorStub(), new LoggerFactory(new[] { log }),
            UrlEncoder.Default, keys, identity);
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        configure(context);
        await handler.InitializeAsync(new AuthenticationScheme("ApiKey", null, typeof(ApiKeyAuthHandler)), context);
        return (await handler.AuthenticateAsync(), log);
    }

    private static IEnumerable<(string Mode, HubIdentityKeys Identity, RealtimeKeys Keys)> AllModes()
    {
        var keys = new RealtimeKeys(Key, ServerKey, acceptPublicKeyOnNotify: true);
        yield return ("legacy", new HubIdentityKeys(null, false, keys), keys);
        yield return ("transition", new HubIdentityKeys(HubKey, true, keys), keys);
        yield return ("enforced", new HubIdentityKeys(HubKey, false, keys), keys);
    }

    /// <summary>The soak noise: the server key on /api/notify used to log a hub refusal on every notify.</summary>
    [Theory]
    [InlineData("/api/notify")]
    [InlineData("/API/Notify")]
    [InlineData("/api/notify/")]
    public async Task NotifyRequest_IsNotJudgedOrLoggedByTheHubScheme(string path)
    {
        foreach (var (mode, identity, keys) in AllModes())
        {
            foreach (var credential in new[] { ServerKey, "wrong-notify-key", Key })
            {
                var (result, log) = await AuthenticateLogged(path, identity, keys,
                    ctx => ctx.Request.Headers["X-Api-Key"] = credential);
                Assert.True(result.None, $"{mode} {path}");
                Assert.DoesNotContain(log.Entries, e => e.Message.Contains("Hub connect refused"));
            }
        }
    }

    /// <summary>Control: the skip is exactly /api/notify, so a hub connect with an unknown key still logs its refusal.</summary>
    [Theory]
    [InlineData("/hubs/elevate")]
    [InlineData("/hubs/elevate/negotiate")]
    [InlineData("/api/notifyall")]
    public async Task HubRequest_WithUnknownKey_StillLogsTheRefusal(string path)
    {
        foreach (var (mode, identity, keys) in AllModes())
        {
            var (result, log) = await AuthenticateLogged(path, identity, keys,
                ctx => ctx.Request.QueryString = new QueryString("?access_token=not-a-known-key"));
            Assert.False(result.Succeeded, mode);
            Assert.False(result.None, mode);
            Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning
                && e.Message.Contains("Hub connect refused") && e.Message.Contains("credential unknown"));
        }
    }

    /// <summary>Hub auth is untouched on the hub path: the public key still connects in legacy and transition.</summary>
    [Fact]
    public async Task HubPath_PublicKey_StillAuthenticates()
    {
        foreach (var (mode, identity, keys) in AllModes().Where(m => m.Mode != "enforced"))
        {
            var (result, _) = await AuthenticateLogged("/hubs/elevate", identity, keys,
                ctx => ctx.Request.QueryString = new QueryString($"?access_token={Key}&userId=u1"));
            Assert.True(result.Succeeded, mode);
        }
    }

    private static void Present(HttpContext context, string carrier, string credential)
    {
        switch (carrier)
        {
            case "bearer": context.Request.Headers["Authorization"] = $"Bearer {credential}"; break;
            case "x-api-key": context.Request.Headers["X-Api-Key"] = credential; break;
            case "access_token": context.Request.QueryString = new QueryString($"?access_token={credential}"); break;
            case "apiKey": context.Request.QueryString = new QueryString($"?apiKey={credential}"); break;
            default: throw new ArgumentOutOfRangeException(nameof(carrier), carrier, null);
        }
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<AuthenticationSchemeOptions>
    {
        public AuthenticationSchemeOptions CurrentValue { get; } = new();
        public AuthenticationSchemeOptions Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<AuthenticationSchemeOptions, string?> listener) => null;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider, ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Entries) Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
