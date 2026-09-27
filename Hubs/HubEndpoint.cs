using Microsoft.AspNetCore.Http.Connections;

namespace ElevateRealtime.Hubs;

/// <summary>Maps /hubs/elevate; token-authenticated connections close when the token expires. See AGENTS.md §H-14 connection lifetime.</summary>
public static class HubEndpoint
{
    public const string Path = "/hubs/elevate";

    /// <summary>Shared with the tests so they exercise the production dispatcher options.</summary>
    public static void ConfigureDispatcher(HttpConnectionDispatcherOptions options)
        => options.CloseOnAuthenticationExpiration = true;

    public static HubEndpointConventionBuilder MapElevateHub(this IEndpointRouteBuilder endpoints)
        => endpoints.MapHub<ElevateHub>(Path, ConfigureDispatcher);
}
