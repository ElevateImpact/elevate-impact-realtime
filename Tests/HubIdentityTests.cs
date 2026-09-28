using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using ElevateRealtime.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ElevateRealtime.Tests;

/// <summary>H-14 hub identity: token verifier, shared vectors, handler modes, boot refusals. See AGENTS.md §H-14.</summary>
public class HubIdentityTests
{
    // Shared with elevate-impact-rewrite tests/unit/lib/server/realtime/hubToken.test.ts: same key + payload => same token.
    private const string VectorKey = "h14-shared-test-vector-key-0123456789abcdef";
    private const string VectorPayload =
        "{\"sub\":\"cvectoruser0000000000001\",\"aud\":\"realtime-hub\",\"iat\":1790000000,\"exp\":1790000300}";
    private const string VectorToken =
        "eyJzdWIiOiJjdmVjdG9ydXNlcjAwMDAwMDAwMDAwMDEiLCJhdWQiOiJyZWFsdGltZS1odWIiLCJpYXQiOjE3OTAwMDAwMDAsImV4cCI6MTc5MDAwMDMwMH0" +
        ".6Cvo4pmKm8Fq8b9BVCD80tkDPbbs1Qen-3BCrcPp1Sg";
    private const long VectorIat = 1790000000;

    private const string PublicKey = "public-browser-key";
    private const string ServerKey = "server-only-key-0123456789abcdefghijklmnop";
    private const string HubKey = "hub-token-key-0123456789abcdefghijklmnopqr";

    private static readonly HubTokens Vector = new(VectorKey);
    private static DateTimeOffset At(long unixSeconds) => DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

    private static string Payload(string sub, long iat, long exp, string aud = "realtime-hub")
        => $"{{\"sub\":\"{sub}\",\"aud\":\"{aud}\",\"iat\":{iat},\"exp\":{exp}}}";

    private static string B64Url(string text)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // ---- shared vector ----

    [Fact]
    public void SharedVector_SignsToTheSameTokenAsTheTypeScriptMinter()
        => Assert.Equal(VectorToken, HubTokens.Sign(VectorKey, VectorPayload));

    [Fact]
    public void SharedVector_Verifies_AndYieldsSub()
    {
        var result = Vector.Verify(VectorToken, At(VectorIat + 100));
        Assert.True(result.Succeeded, result.Failure);
        Assert.Equal("cvectoruser0000000000001", result.UserId);
    }

    // ---- verifier branches ----

    [Fact]
    public void Expired_IsRefused_AfterSkew_AndAcceptedWithinSkew()
    {
        Assert.True(Vector.Verify(VectorToken, At(VectorIat + 300 + HubTokens.ClockSkewSeconds)).Succeeded);
        Assert.Equal("expired", Vector.Verify(VectorToken, At(VectorIat + 300 + HubTokens.ClockSkewSeconds + 1)).Failure);
    }

    [Fact]
    public void IssuedInTheFuture_BeyondSkew_IsRefused()
    {
        Assert.True(Vector.Verify(VectorToken, At(VectorIat - HubTokens.ClockSkewSeconds)).Succeeded);
        Assert.Equal("not-yet-valid", Vector.Verify(VectorToken, At(VectorIat - HubTokens.ClockSkewSeconds - 1)).Failure);
    }

    /// <summary>The verifier bounds exp - iat itself; a key holder minting long tokens is still refused.</summary>
    [Theory]
    [InlineData(901, false)]
    [InlineData(86400, false)]
    [InlineData(0, false)]
    [InlineData(-5, false)]
    [InlineData(900, true)]
    [InlineData(1, true)]
    public void Lifetime_IsBoundedByTheVerifier(long lifetime, bool ok)
    {
        var token = HubTokens.Sign(VectorKey, Payload("u1", VectorIat, VectorIat + lifetime));
        var result = Vector.Verify(token, At(VectorIat));
        Assert.Equal(ok, result.Succeeded);
        if (!ok) Assert.Equal("lifetime", result.Failure);
    }

    [Fact]
    public void WrongAudience_IsRefused()
    {
        var token = HubTokens.Sign(VectorKey, Payload("u1", VectorIat, VectorIat + 300, aud: "notify"));
        Assert.Equal("wrong-audience", Vector.Verify(token, At(VectorIat)).Failure);
    }

    [Fact]
    public void BadSignature_IsRefused()
    {
        var forged = HubTokens.Sign("some-other-key-0123456789abcdefghijklmnop", VectorPayload);
        Assert.Equal("bad-signature", Vector.Verify(forged, At(VectorIat)).Failure);
    }

    [Fact]
    public void TamperedSub_WithOriginalSignature_IsRefused()
    {
        var signature = VectorToken.Split('.')[1];
        var tampered = B64Url(Payload("cvictimuser0000000000002", VectorIat, VectorIat + 300)) + "." + signature;
        Assert.Equal("bad-signature", Vector.Verify(tampered, At(VectorIat)).Failure);
    }

    [Theory]
    [InlineData("")]
    [InlineData("onlyonepart")]
    [InlineData("a.b.c")]
    [InlineData("eyJ9.")]
    public void Malformed_IsRefused(string token)
        => Assert.False(Vector.Verify(token, At(VectorIat)).Succeeded);

    [Fact]
    public void PaddedOrStandardAlphabetOrNonCanonicalEncoding_IsRefused()
    {
        var (payload, signature) = (VectorToken.Split('.')[0], VectorToken.Split('.')[1]);
        Assert.False(Vector.Verify($"{payload}.{signature}=", At(VectorIat)).Succeeded);
        Assert.False(Vector.Verify($"{payload}.{signature.Replace('-', '+')}", At(VectorIat)).Succeeded);
        // Same bytes, different trailing bits: last char 'g' (..000000) -> 'h' (..000001).
        Assert.EndsWith("g", signature);
        Assert.False(Vector.Verify($"{payload}.{signature[..^1]}h", At(VectorIat)).Succeeded);
    }

    [Theory]
    [InlineData("{\"sub\":\"u1\",\"aud\":\"realtime-hub\",\"iat\":1790000000}")]
    [InlineData("{\"sub\":\"u1\",\"aud\":\"realtime-hub\",\"iat\":1790000000,\"exp\":1790000300,\"admin\":true}")]
    [InlineData("{\"sub\":\"u1\",\"sub\":\"u2\",\"aud\":\"realtime-hub\",\"iat\":1790000000,\"exp\":1790000300}")]
    [InlineData("{\"sub\":\"\",\"aud\":\"realtime-hub\",\"iat\":1790000000,\"exp\":1790000300}")]
    [InlineData("{\"sub\":7,\"aud\":\"realtime-hub\",\"iat\":1790000000,\"exp\":1790000300}")]
    [InlineData("{\"sub\":\"u1\",\"aud\":\"realtime-hub\",\"iat\":\"1790000000\",\"exp\":1790000300}")]
    [InlineData("[\"u1\"]")]
    [InlineData("not json")]
    public void SignedButNonCanonicalPayload_IsRefused(string payloadJson)
        => Assert.Equal("malformed", Vector.Verify(HubTokens.Sign(VectorKey, payloadJson), At(VectorIat)).Failure);

    // ---- handler: modes ----

    private static RealtimeKeys Keys() => new(PublicKey, ServerKey, acceptPublicKeyOnNotify: false);
    private static HubIdentityKeys Legacy() => new(null, false, Keys());
    private static HubIdentityKeys Transition() => new(HubKey, true, Keys());
    private static HubIdentityKeys Enforced() => new(HubKey, false, Keys());

    private static string FreshToken(string sub, string key = HubKey)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return HubTokens.Sign(key, Payload(sub, now, now + 300));
    }

    private static async Task<(AuthenticateResult result, CapturingLoggerProvider log)> Authenticate(
        HubIdentityKeys identity, string carrier, string credential, string? assertedUserId = null)
    {
        var log = new CapturingLoggerProvider();
        var handler = new ApiKeyAuthHandler(new OptionsMonitorStub(), new LoggerFactory(new[] { log }),
            UrlEncoder.Default, Keys(), identity);
        var context = new DefaultHttpContext();
        var userIdQuery = assertedUserId is null ? "" : $"&userId={assertedUserId}";
        switch (carrier)
        {
            case "bearer": context.Request.Headers["Authorization"] = $"Bearer {credential}"; context.Request.QueryString = new QueryString($"?x=1{userIdQuery}"); break;
            case "x-api-key": context.Request.Headers["X-Api-Key"] = credential; context.Request.QueryString = new QueryString($"?x=1{userIdQuery}"); break;
            case "access_token": context.Request.QueryString = new QueryString($"?access_token={credential}{userIdQuery}"); break;
            case "apiKey": context.Request.QueryString = new QueryString($"?apiKey={credential}{userIdQuery}"); break;
            default: throw new ArgumentOutOfRangeException(nameof(carrier));
        }
        await handler.InitializeAsync(new AuthenticationScheme("ApiKey", null, typeof(ApiKeyAuthHandler)), context);
        return (await handler.AuthenticateAsync(), log);
    }

    private static string? UserId(AuthenticateResult result) => result.Principal?.FindFirst("userId")?.Value;
    private static string? Method(AuthenticateResult result) => result.Principal?.FindFirst(ClaimTypes.AuthenticationMethod)?.Value;

    [Theory]
    [InlineData("bearer")]
    [InlineData("x-api-key")]
    [InlineData("access_token")]
    [InlineData("apiKey")]
    public async Task ValidToken_Authenticates_AsTokenSub_IgnoringAssertedUserId(string carrier)
    {
        foreach (var identity in new[] { Transition(), Enforced() })
        {
            var (result, _) = await Authenticate(identity, carrier, FreshToken("alice"), assertedUserId: "victim");
            Assert.True(result.Succeeded);
            Assert.Equal("alice", UserId(result));
            Assert.Equal(HubIdentityKeys.MethodHubToken, Method(result));
        }
    }

    [Theory]
    [InlineData("bearer")]
    [InlineData("access_token")]
    public async Task Enforced_RefusesPublicKeyWithAssertedUserId(string carrier)
    {
        var (result, log) = await Authenticate(Enforced(), carrier, PublicKey, assertedUserId: "victim");
        Assert.False(result.Succeeded);
        Assert.Null(result.Principal);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("credential public-key"));
    }

    [Fact]
    public async Task Transition_AcceptsBoth_AndTagsTheLegacyPath()
    {
        var identity = Transition();
        var (legacy, _) = await Authenticate(identity, "access_token", PublicKey, assertedUserId: "bob");
        var (token, _) = await Authenticate(identity, "access_token", FreshToken("alice"));

        Assert.True(legacy.Succeeded);
        Assert.Equal("bob", UserId(legacy));
        Assert.Equal(HubIdentityKeys.MethodAssertedUserId, Method(legacy));
        Assert.True(token.Succeeded);
        Assert.Equal(HubIdentityKeys.MethodHubToken, Method(token));
    }

    /// <summary>Before H-14 variables exist, behaviour is exactly today's: public key + ?userId=.</summary>
    [Fact]
    public async Task Legacy_AcceptsPublicKey_AndRefusesTokens_ItCannotVerify()
    {
        var (legacy, _) = await Authenticate(Legacy(), "access_token", PublicKey, assertedUserId: "bob");
        Assert.True(legacy.Succeeded);
        Assert.Equal("bob", UserId(legacy));

        var (token, _) = await Authenticate(Legacy(), "access_token", FreshToken("alice"));
        Assert.False(token.Succeeded);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InvalidTokens_AreRefused_WithoutFallingBackToAssertedUserId(bool acceptAsserted)
    {
        var identity = new HubIdentityKeys(HubKey, acceptAsserted, Keys());
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var bad in new[]
                 {
                     FreshToken("alice", key: "some-other-key-0123456789abcdefghijklmnop"),
                     HubTokens.Sign(HubKey, Payload("alice", now - 1000, now - 700)),
                     HubTokens.Sign(HubKey, Payload("alice", now, now + 3600)),
                     HubTokens.Sign(HubKey, Payload("alice", now, now + 300, aud: "other")),
                 })
        {
            var (result, log) = await Authenticate(identity, "access_token", bad, assertedUserId: "alice");
            Assert.False(result.Succeeded);
            Assert.Contains(log.Entries, e => e.Message.Contains("credential invalid-token"));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ServerKey_And_HubKey_NeverOpenTheHub(bool acceptAsserted)
    {
        var identity = new HubIdentityKeys(HubKey, acceptAsserted, Keys());
        Assert.False((await Authenticate(identity, "access_token", ServerKey, "u1")).result.Succeeded);
        Assert.False((await Authenticate(identity, "access_token", HubKey, "u1")).result.Succeeded);
    }

    /// <summary>
    /// Wire compatibility (AGENTS.md §H-14 wire). The browser always sends ?userId= and puts ONE credential in
    /// the SignalR access_token slot: a hub token when web mints one, else the public key; after a refused token
    /// it retries once with the public key (signalr.svelte.ts). Row = realtime mode, the two columns = what
    /// the token attempt and the public-key retry yield. A connection is live if either succeeds.
    /// </summary>
    [Theory]
    [InlineData("legacy", false, true)]      // realtime H-14 code, no key yet: token refused, retry connects
    [InlineData("transition", true, true)]   // both work; token wins, retry never needed
    [InlineData("enforced", true, false)]    // token only
    public async Task WireMatrix_EveryDeployOrderKeepsAConnection(string mode, bool tokenAttempt, bool publicKeyRetry)
    {
        var identity = mode switch { "legacy" => Legacy(), "transition" => Transition(), _ => Enforced() };
        var (token, _) = await Authenticate(identity, "access_token", FreshToken("alice"), assertedUserId: "alice");
        var (retry, _) = await Authenticate(identity, "access_token", PublicKey, assertedUserId: "alice");

        Assert.Equal(tokenAttempt, token.Succeeded);
        Assert.Equal(publicKeyRetry, retry.Succeeded);
        Assert.True(token.Succeeded || retry.Succeeded);
        if (token.Succeeded) Assert.Equal("alice", UserId(token));
    }

    // ---- connection lifetime (ticket expiry drives CloseOnAuthenticationExpiration) ----

    [Fact]
    public async Task TokenPath_TicketExpiresWithTheToken_AssertedPathHasNoExpiry()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var token = HubTokens.Sign(HubKey, Payload("alice", now, now + 300));
        var (tokenResult, _) = await Authenticate(Transition(), "access_token", token);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(now + 300), tokenResult.Properties?.ExpiresUtc);

        var (asserted, _) = await Authenticate(Transition(), "access_token", PublicKey, assertedUserId: "bob");
        Assert.True(asserted.Succeeded);
        Assert.Null(asserted.Properties?.ExpiresUtc);
    }

    // ---- rotation: SIGNALR_HUB_TOKEN_KEY_PREVIOUS ----

    private const string NextHubKey = "hub-token-key-NEXT-0123456789abcdefghijklm";

    [Fact]
    public async Task Rotation_PreviousKeyTokensVerify_AndAreTagged_CurrentKeyTokensAreNot()
    {
        var identity = new HubIdentityKeys(NextHubKey, false, Keys(), previousTokenKey: HubKey);
        Assert.True(identity.RotationInProgress);

        var (old, _) = await Authenticate(identity, "access_token", FreshToken("alice", key: HubKey));
        Assert.True(old.Succeeded);
        Assert.Equal("alice", UserId(old));
        Assert.Equal(HubIdentityKeys.MethodHubTokenPreviousKey, Method(old));

        var (current, _) = await Authenticate(identity, "access_token", FreshToken("alice", key: NextHubKey));
        Assert.Equal(HubIdentityKeys.MethodHubToken, Method(current));

        var (other, _) = await Authenticate(identity, "access_token", FreshToken("alice", key: "some-other-key-0123456789abcdefghijklmnop"));
        Assert.False(other.Succeeded);
        Assert.False(Enforced().RotationInProgress);
    }

    [Fact]
    public void Rotation_PreviousKeyStillBoundsLifetimeAndAudience()
    {
        var tokens = new HubTokens(NextHubKey, HubKey);
        var result = tokens.Verify(HubTokens.Sign(HubKey, Payload("u1", VectorIat, VectorIat + 3600)), At(VectorIat));
        Assert.Equal("lifetime", result.Failure);
        result = tokens.Verify(HubTokens.Sign(HubKey, Payload("u1", VectorIat, VectorIat + 300, aud: "x")), At(VectorIat));
        Assert.Equal("wrong-audience", result.Failure);
    }

    [Fact]
    public void Boot_Refuses_UnsafePreviousKey()
    {
        HubIdentityKeys LoadRotation(string? tokenKey, string? previous) => HubIdentityKeys.FromEnvironment(name => name switch
        {
            HubIdentityKeys.TokenKeyVariable => tokenKey,
            HubIdentityKeys.AcceptAssertedUserIdVariable => "false",
            HubIdentityKeys.PreviousTokenKeyVariable => previous,
            _ => null,
        }, Keys());

        Assert.True(LoadRotation(NextHubKey, HubKey).RotationInProgress);
        Assert.False(LoadRotation(NextHubKey, "  ").RotationInProgress);
        Assert.Contains("requires", Assert.Throws<InvalidOperationException>(() => LoadRotation(null, HubKey)).Message);
        Assert.Throws<InvalidOperationException>(() => LoadRotation(NextHubKey, "short"));
        Assert.Contains("must differ from SIGNALR_HUB_TOKEN_KEY",
            Assert.Throws<InvalidOperationException>(() => LoadRotation(NextHubKey, $" {NextHubKey} ")).Message);
        Assert.Contains("must differ", Assert.Throws<InvalidOperationException>(() => LoadRotation(NextHubKey, ServerKey)).Message);
    }

    // ---- per-connection log lines ----

    [Fact]
    public void LogConnection_WarnsOnEveryPreviousKeyConnection()
    {
        var log = new CapturingLoggerProvider();
        var logger = new LoggerFactory(new[] { log }).CreateLogger("hub");
        var identity = new HubIdentityKeys(NextHubKey, false, Keys(), previousTokenKey: HubKey);
        identity.LogConnection(Principal(HubIdentityKeys.MethodHubTokenPreviousKey, "alice"), logger);
        identity.LogConnection(Principal(HubIdentityKeys.MethodHubTokenPreviousKey, "alice"), logger);
        Assert.Equal(2, log.Entries.Count(e => e.Level == LogLevel.Warning && e.Message.Contains(HubIdentityKeys.PreviousKeyToken)));
    }

    // ---- logging: credentials never reach the sink ----

    [Theory]
    [InlineData("?id=abc&access_token=eyJ.sig", "?id=abc&access_token=[redacted]")]
    [InlineData("?access_token=eyJ.sig&userId=u1", "?access_token=[redacted]&userId=u1")]
    [InlineData("?apiKey=public&userId=u1", "?apiKey=[redacted]&userId=u1")]
    [InlineData("?id=abc&userId=u1", "?id=abc&userId=u1")]
    public void Redact_RemovesCredentialQueryValues(string input, string expected)
        => Assert.Equal(expected, CredentialLogSafety.Redact(input));

    [Fact]
    public void LoggingConfig_DropsHostingRequestLines_AndRedactsAnyCredentialProperty()
    {
        var events = new List<Serilog.Events.LogEvent>();
        using var logger = CredentialLogSafety.Configure(new Serilog.LoggerConfiguration())
            .WriteTo.Sink(new DelegateSink(events.Add)).CreateLogger();

        logger.ForContext(Serilog.Core.Constants.SourceContextPropertyName, "Microsoft.AspNetCore.Hosting.Diagnostics")
            .Information("Request starting {QueryString}", "?id=1&access_token=SECRET");
        logger.ForContext(Serilog.Core.Constants.SourceContextPropertyName, "ElevateRealtime.Hubs.ElevateHub")
            .Warning("Something {Url}", "/hubs/elevate?access_token=SECRET");
        logger.ForContext(Serilog.Core.Constants.SourceContextPropertyName, "ElevateRealtime.Hubs.ElevateHub")
            .Information("User {UserId} connected", "alice");

        Assert.Equal(2, events.Count);
        Assert.All(events, e => Assert.DoesNotContain("SECRET", e.RenderMessage()));
        Assert.Contains(events, e => e.RenderMessage().Contains("access_token=[redacted]"));
    }

    private sealed class DelegateSink(Action<Serilog.Events.LogEvent> emit) : Serilog.Core.ILogEventSink
    {
        public void Emit(Serilog.Events.LogEvent logEvent) => emit(logEvent);
    }

    private static ClaimsPrincipal Principal(string method, string userId)
        => new(new ClaimsIdentity(new[] { new Claim(ClaimTypes.AuthenticationMethod, method), new Claim("userId", userId) }, "ApiKey"));

    [Fact]
    public void LogConnection_WarnsOnEveryAssertedIdentity_AndProvesTokenUseOnce()
    {
        var identity = Transition();
        var log = new CapturingLoggerProvider();
        var logger = new LoggerFactory(new[] { log }).CreateLogger("hub");

        identity.LogConnection(Principal(HubIdentityKeys.MethodAssertedUserId, "bob"), logger);
        identity.LogConnection(Principal(HubIdentityKeys.MethodAssertedUserId, "bob"), logger);
        identity.LogConnection(Principal(HubIdentityKeys.MethodHubToken, "alice"), logger);
        identity.LogConnection(Principal(HubIdentityKeys.MethodHubToken, "alice"), logger);

        Assert.Equal(2, log.Entries.Count(e => e.Level == LogLevel.Warning && e.Message.Contains(HubIdentityKeys.LegacyIdentityToken)));
        Assert.Single(log.Entries, e => e.Level == LogLevel.Information && e.Message.Contains(HubIdentityKeys.TokenFirstUseToken));
    }

    // ---- boot ----

    private static HubIdentityKeys Load(string? tokenKey, string? accept, RealtimeKeys? keys = null)
        => HubIdentityKeys.FromEnvironment(name => name switch
        {
            HubIdentityKeys.TokenKeyVariable => tokenKey,
            HubIdentityKeys.AcceptAssertedUserIdVariable => accept,
            _ => null,
        }, keys ?? Keys());

    [Fact]
    public void FromEnvironment_Modes()
    {
        Assert.Equal("legacy", Load(null, null).Mode);
        Assert.Equal("legacy", Load("  ", "true").Mode);
        Assert.Equal("transition", Load(HubKey, "true").Mode);
        Assert.Equal("transition", Load(HubKey, " 1 ").Mode);
        Assert.Equal("enforced", Load(HubKey, "false").Mode);
        Assert.Equal("enforced", Load($" {HubKey}\n", "0").Mode);
        Assert.False(Load(HubKey, "false").AcceptsAssertedUserId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Boot_Refuses_TokenKeySet_WithSwitchBlank(string? accept)
        => Assert.Contains(HubIdentityKeys.AcceptAssertedUserIdVariable,
            Assert.Throws<InvalidOperationException>(() => Load(HubKey, accept)).Message);

    [Theory]
    [InlineData(null, "false")]
    [InlineData("", "0")]
    [InlineData("   ", "false")]
    public void Boot_Refuses_SwitchFalse_WithTokenKeyBlank(string? tokenKey, string accept)
        => Assert.Contains($"{HubIdentityKeys.AcceptAssertedUserIdVariable}=false requires {HubIdentityKeys.TokenKeyVariable}",
            Assert.Throws<InvalidOperationException>(() => Load(tokenKey, accept)).Message);

    [Fact]
    public void Boot_Refuses_TokenKeyEqualToPublicOrServerKey()
    {
        var longPublic = new string('p', 40);
        var keys = new RealtimeKeys(longPublic, ServerKey, true);
        Assert.Contains("must differ", Assert.Throws<InvalidOperationException>(() => Load(longPublic, "true", keys)).Message);
        Assert.Contains("must differ", Assert.Throws<InvalidOperationException>(() => Load(ServerKey, "false", keys)).Message);
        Assert.Contains("must differ", Assert.Throws<InvalidOperationException>(() => Load($" {ServerKey} ", "false", keys)).Message);
    }

    [Fact]
    public void Boot_Refuses_ShortOrPaddedTokenKey_AndUnrecognizedSwitch()
    {
        Assert.Throws<InvalidOperationException>(() => Load(new string('h', HubIdentityKeys.MinTokenKeyLength - 1), "true"));
        Assert.Throws<InvalidOperationException>(() => Load("  " + new string('h', HubIdentityKeys.MinTokenKeyLength - 1) + "  ", "true"));
        Assert.Throws<InvalidOperationException>(() => Load(HubKey, "yes"));
        Assert.Throws<InvalidOperationException>(() => Load(null, "enforced"));
        _ = Load(new string('h', HubIdentityKeys.MinTokenKeyLength), "true");
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
