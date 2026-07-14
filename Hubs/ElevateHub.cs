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

    // Disconnect grace period — window during which a reconnect cancels the
    // pending offline broadcast. Tightened from 15s to 5s default to reduce
    // the false-positive "online" window after a user closes their tab; env
    // var lets ops bump it back up if reconnect storms become a problem.
    private static readonly int _disconnectGraceSeconds =
        int.TryParse(Environment.GetEnvironmentVariable("PRESENCE_DISCONNECT_GRACE_SECONDS"), out var s) && s > 0
            ? s
            : 5;

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
                // Start grace period before broadcasting offline. Configurable
                // via PRESENCE_DISCONNECT_GRACE_SECONDS env var (default 5s).
                var cts = new CancellationTokenSource();
                SetDisconnectTimer(userId, cts);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(_disconnectGraceSeconds), cts.Token);

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

    /// <summary>
    /// Returns the online status of the OTHER participant in each conversation
    /// the caller passes. The result is a list of {userId, isOnline} pairs.
    ///
    /// Scoping (security): each conversation key is validated against the
    /// database — the caller must be a participant in EVERY key they pass, or
    /// that key is silently dropped from the result. Prevents arbitrary
    /// presence lookups; the caller can only see online status for users they
    /// already have a conversation with.
    ///
    /// Called from the client on reconnect and on JoinConversation to
    /// reconcile presence state with the hub (which is the source of truth).
    /// </summary>
    public async Task<object[]> GetConversationPresence(string[] conversationKeys)
    {
        var userId = GetUserId();
        if (string.IsNullOrEmpty(userId) || conversationKeys == null || conversationKeys.Length == 0)
            return Array.Empty<object>();

        // Step 1: parse + structurally filter (caller must be in key).
        var candidatePartnerIds = new List<string>(conversationKeys.Length);
        foreach (var key in conversationKeys)
        {
            if (string.IsNullOrEmpty(key)) continue;
            var parts = key.Split('-', 2);
            if (parts.Length != 2 || string.IsNullOrEmpty(parts[0]) || string.IsNullOrEmpty(parts[1]))
                continue;
            if (parts[0] != userId && parts[1] != userId)
                continue; // caller not in this conversation — silent drop
            var partnerId = parts[0] == userId ? parts[1] : parts[0];
            candidatePartnerIds.Add(partnerId);
        }

        if (candidatePartnerIds.Count == 0)
            return Array.Empty<object>();

        // Step 2: DB-verify each candidate partner actually has a Chat with
        // the caller. Defense in depth — the key format check above already
        // requires the caller's id, but a real Chat row is the ground truth.
        await using var conn = await _db.OpenConnectionAsync();
        var verifiedPartners = await conn.QueryAsync<string>(@"
            SELECT DISTINCT CASE
                WHEN ""fromId"" = @UserId THEN ""toId""
                ELSE ""fromId""
            END AS partner_id
            FROM ""Chat""
            WHERE (""fromId"" = @UserId OR ""toId"" = @UserId)
              AND (""fromId"" = ANY(@PartnerIds) OR ""toId"" = ANY(@PartnerIds))
              AND ""fromId"" IS NOT NULL
              AND ""toId"" IS NOT NULL",
            new { UserId = userId, PartnerIds = candidatePartnerIds.ToArray() });

        var verifiedSet = new HashSet<string>(verifiedPartners);

        // Step 3: build presence pairs for verified partners only.
        var result = new List<object>(verifiedSet.Count);
        foreach (var partnerId in verifiedSet)
        {
            result.Add(new
            {
                userId = partnerId,
                isOnline = _presenceTracker.IsOnline(partnerId),
            });
        }
        return result.ToArray();
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
