using ElevateRealtime.Auth;
using ElevateRealtime.Models;
using Microsoft.AspNetCore.SignalR;

namespace ElevateRealtime.Hubs;

/// <summary>POST /api/notify: NotifyAuth gate + validation, then the caller's fan-out. See AGENTS.md §H-4a.</summary>
public static class NotifyEndpoint
{
    public const string Path = "/api/notify";

    public static IEndpointConventionBuilder MapNotifyEndpoint(
        this IEndpointRouteBuilder endpoints,
        Func<NotifyRequest, IHubContext<ElevateHub, IElevateHubClient>, Task<IResult>> fanOut)
        => endpoints.MapPost(Path, async (
            NotifyRequest request,
            IHubContext<ElevateHub, IElevateHubClient> hubContext,
            RealtimeKeys keys,
            ILoggerFactory loggerFactory,
            HttpContext httpContext) =>
        {
            if (!NotifyAuth.IsAuthorized(httpContext.Request, keys, loggerFactory.CreateLogger("ElevateRealtime.Notify")))
                return Results.Unauthorized();

            if (string.IsNullOrEmpty(request.EventType) || string.IsNullOrEmpty(request.Group))
                return Results.BadRequest(new { error = "eventType and group are required" });

            return await fanOut(request, hubContext);
        });
}
