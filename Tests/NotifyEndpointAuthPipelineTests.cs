using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using ElevateRealtime.Auth;
using ElevateRealtime.Hubs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace ElevateRealtime.Tests;

/// <summary>
/// /api/notify through Program.cs's real auth pipeline (implicit routing, then UseCors, then UseAuthentication with
/// the default ApiKey scheme, then UseAuthorization): the routed marker, not the URL, keeps the hub scheme silent.
/// A fifth test below reads Program.cs itself, since the pipeline this class builds copies that ordering rather than
/// running it. See AGENTS.md §notify-auth-noise.
/// </summary>
public class NotifyEndpointAuthPipelineTests
{
    private const string PublicKey = "public-browser-key";
    private const string ServerKey = "server-only-key-0123456789abcdefghijklmnop";
    private const string HubKey = "hub-token-key-0123456789abcdefghijklmnopqr";
    private const string UnknownKey = "not-a-known-key-5c1e9a";
    private const string HubRefusal = "Hub connect refused";

    private static RealtimeKeys TransitionKeys() => new(PublicKey, ServerKey, acceptPublicKeyOnNotify: true);
    private static RealtimeKeys EnforcedKeys() => new(PublicKey, ServerKey, acceptPublicKeyOnNotify: false);

    /// <summary>Both switches in the same state, as every environment runs them.</summary>
    private static IEnumerable<(string Mode, RealtimeKeys Keys, HubIdentityKeys Identity)> Modes()
    {
        var transition = TransitionKeys();
        yield return ("transition", transition, new HubIdentityKeys(HubKey, true, transition));
        var enforced = EnforcedKeys();
        yield return ("enforced", enforced, new HubIdentityKeys(HubKey, false, enforced));
    }

    private sealed class Pipeline : IAsyncDisposable
    {
        public required WebApplication App { get; init; }
        public required HttpClient Client { get; init; }
        public required CaptureSink Log { get; init; }
        public required Func<int> FanOuts { get; init; }
        public ValueTask DisposeAsync() => App.DisposeAsync();
    }

    /// <summary>Program.cs's wiring for these paths, minus the database: same logging, scheme, singletons, middleware order and maps.</summary>
    private static async Task<Pipeline> StartAsync(RealtimeKeys keys, HubIdentityKeys identity)
    {
        var sink = new CaptureSink();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        // Program.cs's levels + redaction; preserveStaticLogger keeps this app off the shared Log.Logger (parallel test classes).
        builder.Host.UseSerilog((_, lc) => CredentialLogSafety.Configure(lc).WriteTo.Sink(sink), preserveStaticLogger: true);
        builder.Services.AddSignalR();
        builder.Services.AddSingleton(keys);
        builder.Services.AddSingleton(identity);
        builder.Services.AddAuthentication("ApiKey")
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthHandler>("ApiKey", null);
        builder.Services.AddAuthorization();
        // UseCors() throws without this; the default (unconfigured) policy is enough since no request here carries
        // an Origin header — only the middleware ORDER relative to UseAuthentication matters for this suite.
        builder.Services.AddCors();
        var app = builder.Build();
        app.UseCors();
        app.UseAuthentication();
        app.UseAuthorization();
        var fanOuts = 0;
        app.MapNotifyEndpoint((_, _) =>
        {
            Interlocked.Increment(ref fanOuts);
            return Task.FromResult(Results.Ok(new { success = true }));
        });
        // The real [Authorize] hub; a refused negotiate never activates it, so no database is needed.
        app.MapElevateHub();
        await app.StartAsync();
        return new Pipeline { App = app, Client = app.GetTestClient(), Log = sink, FanOuts = () => fanOuts };
    }

    private static Task<HttpResponseMessage> NotifyAsync(HttpClient client, string path, string key)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(new { eventType = "ConversationUpdated", group = "a45-probe", payload = new { } }),
        };
        request.Headers.Add(NotifyAuth.HeaderName, key);
        return client.SendAsync(request);
    }

    /// <summary>The A-45 soak noise, end to end: a server-key notify is authorized by NotifyAuth and the hub scheme logs nothing.</summary>
    [Theory]
    [InlineData("/api/notify")]
    [InlineData("/API/Notify")]
    public async Task ServerKeyNotify_FansOut_AndTheHubSchemeStaysSilent(string path)
    {
        foreach (var (_, keys, identity) in Modes())
        {
            await using var pipeline = await StartAsync(keys, identity);

            var response = await NotifyAsync(pipeline.Client, path, ServerKey);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(1, pipeline.FanOuts());
            // Positive control: the sink sees this request's logging, so the absence below is not vacuous.
            Assert.Contains(pipeline.Log.Events, e => e.Rendered.Contains(NotifyAuth.ServerKeyFirstUseToken));
            Assert.DoesNotContain(pipeline.Log.Events, e => e.Template.StartsWith(HubRefusal));
        }
    }

    /// <summary>H-4a enforced: the public key is refused by NotifyAuth (its own line), still without a hub-scheme refusal.</summary>
    [Fact]
    public async Task PublicKeyNotify_Gets401_InEnforcedMode_FromNotifyAuthOnly()
    {
        var keys = EnforcedKeys();
        await using var pipeline = await StartAsync(keys, new HubIdentityKeys(HubKey, false, keys));

        var response = await NotifyAsync(pipeline.Client, NotifyEndpoint.Path, PublicKey);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, pipeline.FanOuts());
        Assert.Contains(pipeline.Log.Events, e => e.Template.StartsWith("/api/notify refused")
            && e.Property("Credential") == "public-key");
        Assert.DoesNotContain(pipeline.Log.Events, e => e.Template.StartsWith(HubRefusal));
    }

    /// <summary>A path under /api/notify that routes nowhere carries no marker, so the hub scheme judges it (the prefix rule skipped it).</summary>
    [Fact]
    public async Task NotifyLookalikePath_RoutesNowhere_AndIsJudgedByTheHubScheme()
    {
        foreach (var (mode, keys, identity) in Modes())
        {
            await using var pipeline = await StartAsync(keys, identity);

            var response = await NotifyAsync(pipeline.Client, NotifyEndpoint.Path + "/extra", ServerKey);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal(0, pipeline.FanOuts());
            Assert.Contains(pipeline.Log.Events, e => e.Template.StartsWith(HubRefusal)
                && e.Property("Mode") == mode && e.Property("Credential") == "unknown");
        }
    }

    /// <summary>A wrong-method request to /api/notify routes to ASP.NET Core's 405 rejection endpoint, which carries
    /// no marker either, so the hub scheme judges it too — the same "credential unknown" line as a lookalike path.
    /// Per AGENTS.md §notify-auth-noise this is a probe worth looking at, not noise: a correctly-routed POST never
    /// logs it.</summary>
    [Fact]
    public async Task NotifyWrongMethod_Returns405_AndIsJudgedByTheHubScheme()
    {
        foreach (var (mode, keys, identity) in Modes())
        {
            await using var pipeline = await StartAsync(keys, identity);

            var request = new HttpRequestMessage(HttpMethod.Get, NotifyEndpoint.Path);
            request.Headers.Add(NotifyAuth.HeaderName, ServerKey);
            var response = await pipeline.Client.SendAsync(request);

            Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
            Assert.Equal(0, pipeline.FanOuts());
            Assert.Contains(pipeline.Log.Events, e => e.Template.StartsWith(HubRefusal)
                && e.Property("Mode") == mode && e.Property("Credential") == "unknown");
        }
    }

    /// <summary>The hub path is untouched: an unknown key is refused (401) and logs the existing refusal line, never the key.</summary>
    [Fact]
    public async Task HubNegotiate_WithUnknownKey_IsRefused_AndLogsTheRefusalWithoutTheKey()
    {
        foreach (var (mode, keys, identity) in Modes())
        {
            await using var pipeline = await StartAsync(keys, identity);

            var response = await pipeline.Client.PostAsync(
                $"{HubEndpoint.Path}/negotiate?negotiateVersion=1&access_token={UnknownKey}", content: null);

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains(pipeline.Log.Events, e => e.Template.StartsWith(HubRefusal)
                && e.Property("Mode") == mode && e.Property("Credential") == "unknown");
            Assert.DoesNotContain(pipeline.Log.Events, e => e.Everything.Contains(UnknownKey));
        }
    }

    /// <summary>
    /// Source guard, not a pipeline run: StartAsync above copies Program.cs's middleware order rather than executing
    /// Program.cs, so none of the four request tests would notice a real reordering there. Program.cs never calls
    /// UseRouting() today (WebApplication inserts routing implicitly, ahead of UseCors/UseAuthentication/
    /// UseAuthorization — see AGENTS.md §notify-auth-noise), but if one is ever added it must stay before
    /// UseAuthentication(), or the marker check in ApiKeyAuthHandler never sees the routed endpoint and the old
    /// per-notify "credential unknown" noise returns.
    /// </summary>
    [Fact]
    public void ProgramCs_NeverCallsUseRoutingAfterUseAuthentication()
    {
        var source = StripComments(File.ReadAllText(FindProgramCs()));
        // \b-bounded so a token like "UseAuthenticationCore(" can't masquerade as the real call.
        var authenticationMatch = Regex.Match(source, @"\bUseAuthentication\s*\(");
        Assert.True(authenticationMatch.Success, "Program.cs no longer calls UseAuthentication(); update this guard.");

        foreach (Match routingMatch in Regex.Matches(source, @"\bUseRouting\s*\("))
        {
            Assert.True(routingMatch.Index < authenticationMatch.Index,
                "app.UseRouting() must run before app.UseAuthentication() in Program.cs, or ApiKeyAuthHandler " +
                "never sees the routed endpoint and the per-notify \"credential unknown\" noise returns " +
                "(AGENTS.md §notify-auth-noise).");
        }
    }

    /// <summary>Same resolution as NotifyEndpointTests.ProgramCs_MapsNotifyOnlyThroughMapNotifyEndpoint.</summary>
    private static string FindProgramCs()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "ElevateRealtime.csproj");
            if (File.Exists(candidate)) return Path.Combine(dir.FullName, "Program.cs");
        }
        throw new FileNotFoundException("ElevateRealtime.csproj not found above the test output directory");
    }

    /// <summary>
    /// Strips // line comments and /* */ block comments without being fooled by one inside a string literal, e.g.
    /// Program.cs's own $"http://0.0.0.0:{port}". String/char literals are matched and echoed back verbatim before
    /// a bare "//" or "/*" elsewhere ever gets a chance to start a (wrong) comment match.
    /// </summary>
    private static readonly Regex StringOrCommentPattern = new(
        @"""(?:\\.|[^""\\])*""|'(?:\\.|[^'\\])*'|/\*.*?\*/|//[^\n]*",
        RegexOptions.Singleline | RegexOptions.Compiled);

    private static string StripComments(string source) =>
        StringOrCommentPattern.Replace(source, m => m.Value[0] is '"' or '\'' ? m.Value : "");

    /// <summary>Structured capture: template, rendered text and raw property values (Serilog quotes strings when rendering).</summary>
    private sealed class CaptureSink : ILogEventSink
    {
        private readonly List<Captured> _events = new();
        public void Emit(LogEvent logEvent)
        {
            var properties = logEvent.Properties.ToDictionary(p => p.Key,
                p => p.Value is ScalarValue { Value: var value } ? value?.ToString() : p.Value.ToString());
            lock (_events) _events.Add(new Captured(logEvent.MessageTemplate.Text, logEvent.RenderMessage(), properties));
        }
        public Captured[] Events { get { lock (_events) return _events.ToArray(); } }
    }

    private sealed record Captured(string Template, string Rendered, Dictionary<string, string?> Properties)
    {
        public string? Property(string name) => Properties.TryGetValue(name, out var value) ? value : null;
        public string Everything => Rendered + " " + string.Join(" ", Properties.Values);
    }
}
