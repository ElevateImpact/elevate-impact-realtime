using System.Net;
using System.Net.Http.Json;
using ElevateRealtime.Auth;
using ElevateRealtime.Hubs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ElevateRealtime.Tests;

/// <summary>H-4 end to end over HTTP: /api/notify is gated by NotifyAuth, and Program.cs maps it only via MapNotifyEndpoint.</summary>
public class NotifyEndpointTests
{
    private const string PublicKey = "public-browser-key";
    private const string ServerKey = "server-only-key-0123456789abcdefghijklmnop";

    private static async Task<(WebApplication app, HttpClient client, Func<int> fanOutCalls)> StartAsync(RealtimeKeys keys)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSignalR();
        builder.Services.AddSingleton(keys);
        var app = builder.Build();
        var calls = 0;
        app.MapNotifyEndpoint((_, _) =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(Results.Ok(new { success = true }));
        });
        await app.StartAsync();
        return (app, app.GetTestClient(), () => calls);
    }

    private static Task<HttpResponseMessage> PostAsync(HttpClient client, string? key)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, NotifyEndpoint.Path)
        {
            Content = JsonContent.Create(new { eventType = "ConversationUpdated", group = "h4-probe", payload = new { } }),
        };
        if (key is not null) request.Headers.Add(NotifyAuth.HeaderName, key);
        return client.SendAsync(request);
    }

    [Fact]
    public async Task Enforced_PublicKeyGets401_ServerKeyGets200()
    {
        var (app, client, fanOutCalls) = await StartAsync(new RealtimeKeys(PublicKey, ServerKey, acceptPublicKeyOnNotify: false));
        await using var _ = app;

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(client, PublicKey)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(client, null)).StatusCode);
        Assert.Equal(0, fanOutCalls());

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(client, ServerKey)).StatusCode);
        Assert.Equal(1, fanOutCalls());
    }

    [Fact]
    public async Task Transition_PublicKeyGets200()
    {
        var (app, client, fanOutCalls) = await StartAsync(new RealtimeKeys(PublicKey, ServerKey, acceptPublicKeyOnNotify: true));
        await using var _ = app;

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(client, PublicKey)).StatusCode);
        Assert.Equal(1, fanOutCalls());
    }

    /// <summary>Guards the wiring: a raw MapPost("/api/notify") in Program.cs would bypass NotifyAuth.</summary>
    [Fact]
    public void ProgramCs_MapsNotifyOnlyThroughMapNotifyEndpoint()
    {
        var source = File.ReadAllText(FindProgramCs());
        Assert.Contains("app.MapNotifyEndpoint(", source);
        Assert.DoesNotContain("\"/api/notify\"", source);
    }

    private static string FindProgramCs()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "ElevateRealtime.csproj");
            if (File.Exists(candidate)) return Path.Combine(dir.FullName, "Program.cs");
        }
        throw new FileNotFoundException("ElevateRealtime.csproj not found above the test output directory");
    }
}
