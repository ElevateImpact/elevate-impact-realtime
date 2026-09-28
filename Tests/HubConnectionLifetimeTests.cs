using ElevateRealtime.Auth;
using ElevateRealtime.Hubs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace ElevateRealtime.Tests;

/// <summary>
/// H-14 over a real SignalR connection (TestServer + .NET client, credential in ?access_token= like the browser):
/// token connections close at token expiry and reconnect on a fresh token; asserted connections are unbounded;
/// the token never reaches the logs. See AGENTS.md §H-14 connection lifetime / logging.
/// </summary>
public class HubConnectionLifetimeTests
{
    private const string PublicKey = "public-browser-key";
    private const string ServerKey = "server-only-key-0123456789abcdefghijklmnop";
    private const string HubKey = "hub-token-key-0123456789abcdefghijklmnopqr";
    private const string ProbePath = "/hubs/probe";
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(20);

    [Authorize]
    public sealed class ProbeHub : Hub
    {
        public string? WhoAmI() => Context.User?.FindFirst("userId")?.Value;
    }

    private sealed class CaptureSink : ILogEventSink
    {
        private readonly List<string> _lines = new();
        public void Emit(LogEvent logEvent)
        {
            var line = logEvent.RenderMessage() + " " + string.Join(" ", logEvent.Properties.Values);
            lock (_lines) _lines.Add(line);
        }
        public string[] Lines { get { lock (_lines) return _lines.ToArray(); } }
    }

    private static async Task<(WebApplication app, TestServer server)> StartAsync(
        HubIdentityKeys identity, Func<LoggerConfiguration, LoggerConfiguration> logging, CaptureSink sink)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Host.UseSerilog((_, lc) => logging(lc).WriteTo.Sink(sink));
        builder.Services.AddSignalR();
        builder.Services.AddSingleton(new RealtimeKeys(PublicKey, ServerKey, acceptPublicKeyOnNotify: false));
        builder.Services.AddSingleton(identity);
        builder.Services.AddAuthentication("ApiKey")
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthHandler>("ApiKey", null);
        builder.Services.AddAuthorization();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        // Production dispatcher options (CloseOnAuthenticationExpiration) on a DB-free probe hub.
        app.MapHub<ProbeHub>(ProbePath, HubEndpoint.ConfigureDispatcher);
        await app.StartAsync();
        return (app, app.GetTestServer());
    }

    /// <summary>Like the browser: WebSockets, credential from the factory in ?access_token=, fresh per (re)connect.</summary>
    private static HubConnection Connect(TestServer server, Func<string> credential, string assertedUserId)
        => new HubConnectionBuilder()
            .WithUrl(new Uri(server.BaseAddress, $"{ProbePath.TrimStart('/')}?userId={assertedUserId}"), options =>
            {
                options.Transports = HttpTransportType.WebSockets;
                options.HttpMessageHandlerFactory = _ => server.CreateHandler();
                options.AccessTokenProvider = () => Task.FromResult<string?>(credential());
                options.WebSocketFactory = async (context, cancellationToken) =>
                {
                    var uri = new UriBuilder(context.Uri) { Scheme = "http" };
                    uri.Query = uri.Query.TrimStart('?') + "&access_token=" + Uri.EscapeDataString(credential());
                    return await server.CreateWebSocketClient().ConnectAsync(uri.Uri, cancellationToken);
                };
            })
            .WithAutomaticReconnect(new[] { TimeSpan.Zero, TimeSpan.FromMilliseconds(200) })
            .Build();

    private static string Token(string sub, int lifetimeSeconds)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return HubTokens.Sign(HubKey,
            $"{{\"sub\":\"{sub}\",\"aud\":\"realtime-hub\",\"iat\":{now},\"exp\":{now + lifetimeSeconds}}}");
    }

    private static Task<T> Within<T>(TaskCompletionSource<T> source)
        => source.Task.WaitAsync(Wait);

    [Fact]
    public async Task TokenConnection_ClosesAtExpiry_AndReconnectsOnAFreshToken_WhileAssertedConnectionStaysUp()
    {
        var sink = new CaptureSink();
        var (app, server) = await StartAsync(new HubIdentityKeys(HubKey, true, new RealtimeKeys(PublicKey, ServerKey, false)),
            CredentialLogSafety.Configure, sink);
        await using var _ = app;

        // First token lives 2 s; later ones 300 s, so the post-reconnect asserts do not race a second expiry.
        var minted = 0;
        await using var tokenConnection = Connect(server,
            () => Token("alice", Interlocked.Increment(ref minted) <= 2 ? 2 : 300), "victim");
        await using var assertedConnection = Connect(server, () => PublicKey, "bob");
        var reconnecting = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reconnected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var closed = false;
        var assertedDropped = false;
        tokenConnection.Reconnecting += _ => { reconnecting.TrySetResult(true); return Task.CompletedTask; };
        tokenConnection.Reconnected += _ => { reconnected.TrySetResult(true); return Task.CompletedTask; };
        tokenConnection.Closed += _ => { closed = true; return Task.CompletedTask; };
        assertedConnection.Reconnecting += _ => { assertedDropped = true; return Task.CompletedTask; };
        assertedConnection.Closed += _ => { assertedDropped = true; return Task.CompletedTask; };

        await tokenConnection.StartAsync();
        await assertedConnection.StartAsync();
        Assert.Equal("alice", await tokenConnection.InvokeAsync<string>("WhoAmI"));
        var mintedBeforeExpiry = minted;

        await Within(reconnecting);
        await Within(reconnected);
        Assert.False(closed);
        Assert.True(minted > mintedBeforeExpiry, "the reconnect must fetch a fresh token");
        Assert.Equal("alice", await tokenConnection.InvokeAsync<string>("WhoAmI"));

        // The asserted path gets no ticket expiry: unchanged pre-H-14 behaviour in legacy/transition.
        Assert.False(assertedDropped);
        Assert.Equal(HubConnectionState.Connected, assertedConnection.State);
        Assert.Equal("bob", await assertedConnection.InvokeAsync<string>("WhoAmI"));
    }

    /// <summary>Logout or a leaked token: once no fresh token can be minted, the socket dies at expiry.</summary>
    [Fact]
    public async Task TokenConnection_DiesAtExpiry_WhenNoFreshTokenCanBeMinted()
    {
        var sink = new CaptureSink();
        var (app, server) = await StartAsync(new HubIdentityKeys(HubKey, false, new RealtimeKeys(PublicKey, ServerKey, false)),
            CredentialLogSafety.Configure, sink);
        await using var _ = app;

        var leaked = Token("alice", 2);
        var sessionAlive = true;
        await using var connection = Connect(server,
            () => sessionAlive ? leaked : throw new InvalidOperationException("hub token unavailable (401)"), "alice");
        var closedSource = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        connection.Closed += _ => { closedSource.TrySetResult(true); return Task.CompletedTask; };

        await connection.StartAsync();
        sessionAlive = false;
        await Within(closedSource);
        Assert.Equal(HubConnectionState.Disconnected, connection.State);
    }

    [Fact]
    public async Task HubToken_NeverReachesTheLogs_ButWouldWithoutCredentialLogSafety()
    {
        async Task<(string token, string[] lines)> ConnectOnce(Func<LoggerConfiguration, LoggerConfiguration> logging)
        {
            var sink = new CaptureSink();
            var (app, server) = await StartAsync(
                new HubIdentityKeys(HubKey, false, new RealtimeKeys(PublicKey, ServerKey, false)), logging, sink);
            await using var _ = app;
            var token = Token("alice", 300);
            await using var connection = Connect(server, () => token, "alice");
            await connection.StartAsync();
            Assert.Equal("alice", await connection.InvokeAsync<string>("WhoAmI"));
            await connection.StopAsync();
            return (token, sink.Lines);
        }

        // Control: the pre-fix config (Information, no overrides) logs the WebSocket URL with the token.
        var (controlToken, controlLines) = await ConnectOnce(lc => lc.MinimumLevel.Information());
        Assert.Contains(controlLines, line => line.Contains(controlToken.Split('.')[1]));

        var (token, lines) = await ConnectOnce(CredentialLogSafety.Configure);
        Assert.DoesNotContain(lines, line => line.Contains(token.Split('.')[1]) || line.Contains(token.Split('.')[0]));
        Assert.DoesNotContain(lines, line => line.Contains("access_token=ey"));
    }
}
