using System.Collections.Concurrent;

namespace ElevateRealtime.Services;

public class PresenceTracker
{
    private readonly ConcurrentDictionary<string, HashSet<string>> _onlineUsers = new();
    private readonly object _lock = new();

    /// <summary>
    /// Track a user connection. Returns true if this is the user's first connection (went from 0 to 1).
    /// </summary>
    public bool UserConnected(string userId, string connectionId)
    {
        lock (_lock)
        {
            if (!_onlineUsers.TryGetValue(userId, out var connections))
            {
                connections = new HashSet<string>();
                _onlineUsers[userId] = connections;
            }

            connections.Add(connectionId);
            return connections.Count == 1;
        }
    }

    /// <summary>
    /// Remove a user connection. Returns true if the user has 0 connections remaining.
    /// </summary>
    public bool UserDisconnected(string userId, string connectionId)
    {
        lock (_lock)
        {
            if (!_onlineUsers.TryGetValue(userId, out var connections))
                return true;

            connections.Remove(connectionId);

            if (connections.Count == 0)
            {
                _onlineUsers.TryRemove(userId, out _);
                return true;
            }

            return false;
        }
    }

    public bool IsOnline(string userId)
    {
        return _onlineUsers.TryGetValue(userId, out var connections) && connections.Count > 0;
    }

    /// <summary>
    /// Returns the subset of userIds that are currently online.
    /// </summary>
    public string[] GetOnlineUsers(IEnumerable<string> userIds)
    {
        return userIds.Where(IsOnline).ToArray();
    }
}
