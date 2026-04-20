using Dapper;
using ElevateRealtime.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Npgsql;

namespace ElevateRealtime.Hubs;

[Authorize]
public class ElevateHub : Hub<IElevateHubClient>
{
    private readonly NpgsqlDataSource _db;
    private readonly PresenceTracker _presenceTracker;
    private readonly ILogger<ElevateHub> _logger;

    // Grace period timers for presence (keyed by userId)
    private static readonly Dictionary<string, CancellationTokenSource> _disconnectTimers = new();
    private static readonly object _timerLock = new();

    public ElevateHub(NpgsqlDataSource db, PresenceTracker presenceTracker, ILogger<ElevateHub> logger)
    {
        _db = db;
        _presenceTracker = presenceTracker;
        _logger = logger;
    }

    public override async Task OnConnectedAsync()
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId))
        {
            throw new HubException("userId is required");
        }

        // Validate user exists in database
        await using var conn = await _db.OpenConnectionAsync();
        var exists = await conn.ExecuteScalarAsync<int>(
            "SELECT 1 FROM \"User\" WHERE id = @Id LIMIT 1",
            new { Id = userId });

        if (exists == 0)
        {
            throw new HubException("User not found");
        }

        // Add to user group
        await Groups.AddToGroupAsync(Context.ConnectionId, $"user:{userId}");

        // Cancel any pending disconnect timer
        CancelDisconnectTimer(userId);

        // Track presence
        var isFirstConnection = _presenceTracker.UserConnected(userId, Context.ConnectionId);

        if (isFirstConnection)
        {
            // Broadcast online to conversation partners
            var partnerIds = await GetConversationPartnerIds(conn, userId);
            foreach (var partnerId in partnerIds)
            {
                await Clients.Group($"user:{partnerId}").UserPresenceChanged(
                    new { userId, isOnline = true });
            }
        }

        _logger.LogInformation("User {UserId} connected (ConnectionId: {ConnectionId})",
            userId, Context.ConnectionId);

        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var userId = GetUserId();
        if (!string.IsNullOrEmpty(userId))
        {
            var hasNoConnections = _presenceTracker.UserDisconnected(userId, Context.ConnectionId);

            if (hasNoConnections)
            {
                // Start 15-second grace period before broadcasting offline
                var cts = new CancellationTokenSource();
                SetDisconnectTimer(userId, cts);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(15), cts.Token);

                        // After grace period, check if still offline
                        if (!_presenceTracker.IsOnline(userId))
                        {
                            await using var conn = await _db.OpenConnectionAsync();
                            var partnerIds = await GetConversationPartnerIds(conn, userId);
                            foreach (var partnerId in partnerIds)
                            {
                                await Clients.Group($"user:{partnerId}").UserPresenceChanged(
                                    new { userId, isOnline = false });
                            }
                        }
                    }
                    catch (TaskCanceledException)
                    {
                        // User reconnected, timer cancelled
                    }
                });
            }

            _logger.LogInformation("User {UserId} disconnected (ConnectionId: {ConnectionId})",
                userId, Context.ConnectionId);
        }

        await base.OnDisconnectedAsync(exception);
    }

    public async Task JoinConversation(string conversationKey)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId))
            throw new HubException("userId is required");

        // Validate key format: {id1}-{id2} where ids are sorted
        var parts = conversationKey.Split('-', 2);
        if (parts.Length != 2 || string.IsNullOrEmpty(parts[0]) || string.IsNullOrEmpty(parts[1]))
            throw new HubException("Invalid conversation key format");

        // Verify the calling user is one of the participants
        if (parts[0] != userId && parts[1] != userId)
            throw new HubException("You are not a participant in this conversation");

        await Groups.AddToGroupAsync(Context.ConnectionId, $"conversation:{conversationKey}");

        _logger.LogInformation("User {UserId} joined conversation {ConversationKey}",
            userId, conversationKey);
    }

    public async Task LeaveConversation(string conversationKey)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"conversation:{conversationKey}");

        _logger.LogInformation("Connection {ConnectionId} left conversation {ConversationKey}",
            Context.ConnectionId, conversationKey);
    }

    public async Task SendTypingIndicator(string conversationKey, bool isTyping)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return;

        await Clients.OthersInGroup($"conversation:{conversationKey}").TypingIndicatorReceived(
            new { userId, conversationKey, isTyping });
    }

    public async Task MarkAsRead(string conversationKey, string messageId)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId)) return;

        await Clients.Group($"conversation:{conversationKey}").ReadReceiptReceived(
            new { userId, conversationKey, messageId, readAt = DateTime.UtcNow });
    }

    public string[] GetOnlineUsers(string[] userIds)
    {
        return _presenceTracker.GetOnlineUsers(userIds);
    }

    private string? GetUserId()
    {
        return Context.User?.FindFirst("userId")?.Value
               ?? Context.GetHttpContext()?.Request.Query["userId"].FirstOrDefault();
    }

    private static async Task<string[]> GetConversationPartnerIds(NpgsqlConnection conn, string userId)
    {
        var sql = @"
            SELECT DISTINCT CASE
                WHEN ""fromId"" = @UserId THEN ""toId""
                ELSE ""fromId""
            END AS partner_id
            FROM ""Chat""
            WHERE (""fromId"" = @UserId OR ""toId"" = @UserId)
              AND ""fromId"" IS NOT NULL
              AND ""toId"" IS NOT NULL";

        var partners = await conn.QueryAsync<string>(sql, new { UserId = userId });
        return partners.ToArray();
    }

    private static void CancelDisconnectTimer(string userId)
    {
        lock (_timerLock)
        {
            if (_disconnectTimers.TryGetValue(userId, out var cts))
            {
                cts.Cancel();
                cts.Dispose();
                _disconnectTimers.Remove(userId);
            }
        }
    }

    private static void SetDisconnectTimer(string userId, CancellationTokenSource cts)
    {
        lock (_timerLock)
        {
            CancelDisconnectTimer(userId);
            _disconnectTimers[userId] = cts;
        }
    }
}
