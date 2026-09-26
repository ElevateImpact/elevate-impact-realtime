using ElevateRealtime.Auth;
using ElevateRealtime.Hubs;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Xunit;

namespace ElevateRealtime.Tests;

/// <summary>H-4 key split: notify auth per mode, boot refusals, key trimming. See AGENTS.md §H-4a.</summary>
public class NotifyKeySplitTests
{
    private const string PublicKey = "public-browser-key";
    private const string ServerKey = "server-only-key-0123456789abcdefghijklmnop";

    private static RealtimeKeys Legacy() => new(PublicKey, null, false);
    private static RealtimeKeys Transition() => new(PublicKey, ServerKey, true);
    private static RealtimeKeys Enforced() => new(PublicKey, ServerKey, false);

    private static (bool authorized, CapturingLogger log) Notify(RealtimeKeys keys, string? headerValue)
    {
        var context = new DefaultHttpContext();
        if (headerValue is not null)
            context.Request.Headers[NotifyAuth.HeaderName] = headerValue;
        var log = new CapturingLogger();
        return (NotifyAuth.IsAuthorized(context.Request, keys, log), log);
    }

    // ---- notify: server key ----

    [Fact]
    public void ServerKey_AcceptedOnNotify_InTransitionAndEnforced_WithoutLegacyWarning()
    {
        foreach (var keys in new[] { Transition(), Enforced() })
        {
            var (ok, log) = Notify(keys, ServerKey);
            Assert.True(ok);
            Assert.DoesNotContain(log.Entries, e => e.Message.Contains(NotifyAuth.LegacyWarningToken));
        }
    }

    [Fact]
    public void ServerKey_FirstUse_LogsProofLineExactlyOnce()
    {
        var keys = Enforced();
        var (_, firstLog) = Notify(keys, ServerKey);
        var (_, secondLog) = Notify(keys, ServerKey);
        Assert.Single(firstLog.Entries, e => e.Level == LogLevel.Information && e.Message.Contains(NotifyAuth.ServerKeyFirstUseToken));
        Assert.Empty(secondLog.Entries);
    }

    // ---- notify: public key ----

    [Fact]
    public void PublicKey_RefusedOnNotify_InEnforcedEndState()
    {
        var (ok, log) = Notify(Enforced(), PublicKey);
        Assert.False(ok);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("public-key"));
    }

    [Fact]
    public void PublicKey_AcceptedOnNotify_InTransition_AndWarnsEveryTime()
    {
        var keys = Transition();
        var (first, firstLog) = Notify(keys, PublicKey);
        var (second, secondLog) = Notify(keys, PublicKey);

        Assert.True(first);
        Assert.True(second);
        Assert.Single(firstLog.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains(NotifyAuth.LegacyWarningToken));
        Assert.Single(secondLog.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains(NotifyAuth.LegacyWarningToken));
    }

    /// <summary>Deploying the new code with no new variables changes nothing (step 1 of the runbook).</summary>
    [Fact]
    public void PublicKey_AcceptedOnNotify_InLegacyMode_WithWarning()
    {
        var (ok, log) = Notify(Legacy(), PublicKey);
        Assert.True(ok);
        Assert.Contains(log.Entries, e => e.Message.Contains(NotifyAuth.LegacyWarningToken));
    }

    [Fact]
    public void WrongOrMissingKey_RefusedOnNotify_InEveryMode()
    {
        foreach (var keys in new[] { Legacy(), Transition(), Enforced() })
        {
            Assert.False(Notify(keys, "nope").authorized);
            Assert.False(Notify(keys, null).authorized);
            Assert.False(Notify(keys, "").authorized);
        }
    }

    // ---- modes ----

    [Fact]
    public void Mode_ReflectsConfiguration()
    {
        Assert.Equal("legacy", Legacy().Mode);
        Assert.Equal("transition", Transition().Mode);
        Assert.Equal("enforced", Enforced().Mode);
        Assert.True(Legacy().AcceptsPublicKeyOnNotify);
        Assert.False(Enforced().AcceptsPublicKeyOnNotify);
    }

    private static RealtimeKeys Load(string? server, string? accept, string publicKey = PublicKey)
        => RealtimeKeys.FromEnvironment(name => name switch
        {
            RealtimeKeys.PublicKeyVariable => publicKey,
            RealtimeKeys.ServerKeyVariable => server,
            RealtimeKeys.AcceptPublicKeyOnNotifyVariable => accept,
            _ => null,
        });

    [Fact]
    public void FromEnvironment_ParsesSwitchAndTreatsBlankServerKeyAsUnset()
    {
        Assert.Equal("legacy", Load(null, null).Mode);
        Assert.Equal("legacy", Load("  ", "true").Mode);
        Assert.Equal("legacy", Load(null, "true").Mode);
        Assert.Equal("transition", Load(ServerKey, "true").Mode);
        Assert.Equal("transition", Load(ServerKey, " TRUE ").Mode);
        Assert.Equal("transition", Load(ServerKey, "1").Mode);
        Assert.Equal("enforced", Load(ServerKey, "false").Mode);
        Assert.Equal("enforced", Load(ServerKey, "0").Mode);
    }

    /// <summary>A lone SIGNALR_SERVER_KEY write must fail the deploy, not silently jump to enforced.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Boot_Refuses_ServerKeySet_WithSwitchBlank(string? accept)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Load(ServerKey, accept));
        Assert.Contains(RealtimeKeys.AcceptPublicKeyOnNotifyVariable, ex.Message);
    }

    /// <summary>Enforced must fail closed: a deleted, blanked or dangling-reference key cannot reopen legacy.</summary>
    [Theory]
    [InlineData(null, "false")]
    [InlineData("", "false")]
    [InlineData("   ", "0")]
    public void Boot_Refuses_SwitchFalse_WithServerKeyBlank(string? server, string accept)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Load(server, accept));
        Assert.Contains($"{RealtimeKeys.AcceptPublicKeyOnNotifyVariable}=false requires {RealtimeKeys.ServerKeyVariable}", ex.Message);
    }

    // ---- normalization (matches notify.ts, which trims) ----

    [Fact]
    public void Keys_AreTrimmed_OnBothConfigAndPresentedSides()
    {
        var keys = Load($"{ServerKey}\n", "false", publicKey: $" {PublicKey}\r\n");
        Assert.True(keys.IsPublicKey(PublicKey));
        Assert.True(keys.IsPublicKey($"{PublicKey} "));
        Assert.Equal(NotifyAuthorization.ServerKey, keys.AuthorizeNotify(ServerKey));
        Assert.Equal(NotifyAuthorization.ServerKey, keys.AuthorizeNotify($" {ServerKey}\n"));
        Assert.Equal(NotifyAuthorization.Refused, keys.AuthorizeNotify($"{PublicKey}\n"));
    }

    [Fact]
    public void Boot_Refuses_ServerKeyPaddedToMinimumWithWhitespace_AndWhitespaceOnlyPublicKey()
    {
        var padded = "  " + new string('s', RealtimeKeys.MinServerKeyLength - 1) + "  ";
        Assert.Throws<InvalidOperationException>(() => Load(padded, "true"));
        Assert.Throws<InvalidOperationException>(() => Load(null, null, publicKey: "   "));
        var longKey = new string('k', 40);
        Assert.Throws<InvalidOperationException>(() => new RealtimeKeys(longKey, longKey + " ", true));
    }

    // ---- boot refusals ----

    [Fact]
    public void Boot_Refuses_ServerKeyEqualToPublicKey()
    {
        var sameLongKey = new string('k', 40);
        var ex = Assert.Throws<InvalidOperationException>(() => new RealtimeKeys(sameLongKey, sameLongKey, true));
        Assert.Contains("must differ", ex.Message);
    }

    [Fact]
    public void Boot_Refuses_ShortServerKey()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => new RealtimeKeys(PublicKey, new string('s', RealtimeKeys.MinServerKeyLength - 1), true));
        Assert.Contains("at least", ex.Message);
        _ = new RealtimeKeys(PublicKey, new string('s', RealtimeKeys.MinServerKeyLength), true);
    }

    [Fact]
    public void Boot_Refuses_MissingPublicKey_And_UnrecognizedSwitch()
    {
        Assert.Throws<InvalidOperationException>(() => RealtimeKeys.FromEnvironment(_ => null));
        Assert.Throws<InvalidOperationException>(() => RealtimeKeys.FromEnvironment(name => name switch
        {
            RealtimeKeys.PublicKeyVariable => PublicKey,
            RealtimeKeys.ServerKeyVariable => ServerKey,
            RealtimeKeys.AcceptPublicKeyOnNotifyVariable => "yes",
            _ => null,
        }));
    }

    // ---- hub: consistency check only (userId is self-asserted until H-4b) ----

    [Theory]
    [InlineData("alice-bob", "alice", true)]
    [InlineData("alice-bob", "bob", true)]
    [InlineData("alice-bob", "mallory", false)]
    [InlineData("alicebob", "alice", false)]
    [InlineData("-bob", "bob", false)]
    [InlineData("", "alice", false)]
    [InlineData(null, "alice", false)]
    public void IsParticipant_RequiresKeyToContainClaimedUserId(string? key, string userId, bool expected)
        => Assert.Equal(expected, ElevateHub.IsParticipant(key, userId));

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }
}
