using ElevateRealtime.Auth;
using ElevateRealtime.Config;
using ElevateRealtime.Hubs;
using ElevateRealtime.Models;
using ElevateRealtime.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.SignalR;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Environment variables
var databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL")
    ?? throw new InvalidOperationException("DATABASE_URL is required");
var signalrApiKey = Environment.GetEnvironmentVariable("SIGNALR_API_KEY")
    ?? throw new InvalidOperationException("SIGNALR_API_KEY is required");
var allowedOrigins = Environment.GetEnvironmentVariable("ALLOWED_ORIGINS")
    ?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    ?? Array.Empty<string>();
var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";

// Parse Railway DATABASE_URL to Npgsql connection string
var connectionString = DatabaseConfig.ParseRailwayConnectionString(databaseUrl);

// Database - register NpgsqlDataSource as singleton
var dataSourceBuilder = new Npgsql.NpgsqlDataSourceBuilder(connectionString);
var dataSource = dataSourceBuilder.Build();
builder.Services.AddSingleton(dataSource);

// Serilog
builder.Host.UseSerilog((ctx, lc) => lc
    .WriteTo.Console()
    .MinimumLevel.Information());

// SignalR
builder.Services.AddSignalR();

// Presence tracker (singleton, in-memory)
builder.Services.AddSingleton<PresenceTracker>();

// API key config
builder.Services.AddSingleton(new ApiKeyConfig(signalrApiKey));

// Authentication
builder.Services.AddAuthentication("ApiKey")
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthHandler>("ApiKey", null);
builder.Services.AddAuthorization();

// CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// Health check endpoint
app.MapGet("/api/health", async (Npgsql.NpgsqlDataSource db, ILogger<Program> logger) =>
{
    try
    {
        await using var conn = await db.OpenConnectionAsync();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1";
        await cmd.ExecuteScalarAsync();
        return Results.Ok(new { status = "healthy" });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Health check failed");
        return Results.Json(new { status = "unhealthy", error = ex.Message }, statusCode: 503);
    }
});

// Notify endpoint (server-to-server, API key protected)
app.MapPost("/api/notify", async (
    NotifyRequest request,
    IHubContext<ElevateHub, IElevateHubClient> hubContext,
    ApiKeyConfig apiKeyConfig,
    HttpContext httpContext) =>
{
    // Validate API key from header
    var apiKey = httpContext.Request.Headers["X-Api-Key"].FirstOrDefault();
    if (string.IsNullOrEmpty(apiKey) || apiKey != apiKeyConfig.Key)
        return Results.Unauthorized();

    if (string.IsNullOrEmpty(request.EventType) || string.IsNullOrEmpty(request.Group))
        return Results.BadRequest(new { error = "eventType and group are required" });

    switch (request.EventType)
    {
        case "MessageReceived":
            await hubContext.Clients.Group(request.Group).MessageReceived(request.Payload!);
            if (request.UserGroups != null)
            {
                foreach (var userGroup in request.UserGroups)
                    await hubContext.Clients.Group($"user:{userGroup}").MessageReceived(request.Payload!);
            }
            break;

        case "MessageDeleted":
            await hubContext.Clients.Group(request.Group).MessageDeleted(request.Payload!);
            if (request.UserGroups != null)
            {
                foreach (var userGroup in request.UserGroups)
                    await hubContext.Clients.Group($"user:{userGroup}").MessageDeleted(request.Payload!);
            }
            break;

        case "ReadReceiptReceived":
            await hubContext.Clients.Group(request.Group).ReadReceiptReceived(request.Payload!);
            break;

        case "ConversationUpdated":
            await hubContext.Clients.Group(request.Group).ConversationUpdated(request.Payload!);
            break;

        case "SamThinkingStarted":
            await hubContext.Clients.Group(request.Group).SamThinkingStarted(request.Payload!);
            break;

        case "SamThinkingStopped":
            await hubContext.Clients.Group(request.Group).SamThinkingStopped(request.Payload!);
            break;

        default:
            return Results.BadRequest(new { error = $"Unknown event type: {request.EventType}" });
    }

    return Results.Ok(new { success = true });
});

// Map SignalR hub
app.MapHub<ElevateHub>("/hubs/elevate");

app.Run($"http://0.0.0.0:{port}");
