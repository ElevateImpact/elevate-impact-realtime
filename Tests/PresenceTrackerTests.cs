using Xunit;
using ElevateRealtime.Services;

namespace ElevateRealtime.Tests;

public class PresenceTrackerTests
{
    [Fact]
    public void UserConnected_FirstConnection_ReturnsTrue()
    {
        var tracker = new PresenceTracker();
        var result = tracker.UserConnected("user1", "conn1");
        Assert.True(result);
    }

    [Fact]
    public void UserConnected_SecondConnection_ReturnsFalse()
    {
        var tracker = new PresenceTracker();
        tracker.UserConnected("user1", "conn1");
        var result = tracker.UserConnected("user1", "conn2");
        Assert.False(result);
    }

    [Fact]
    public void UserDisconnected_LastConnection_ReturnsTrue()
    {
        var tracker = new PresenceTracker();
        tracker.UserConnected("user1", "conn1");
        var result = tracker.UserDisconnected("user1", "conn1");
        Assert.True(result);
    }

    [Fact]
    public void UserDisconnected_StillHasConnections_ReturnsFalse()
    {
        var tracker = new PresenceTracker();
        tracker.UserConnected("user1", "conn1");
        tracker.UserConnected("user1", "conn2");
        var result = tracker.UserDisconnected("user1", "conn1");
        Assert.False(result);
    }

    [Fact]
    public void IsOnline_ConnectedUser_ReturnsTrue()
    {
        var tracker = new PresenceTracker();
        tracker.UserConnected("user1", "conn1");
        Assert.True(tracker.IsOnline("user1"));
    }

    [Fact]
    public void IsOnline_DisconnectedUser_ReturnsFalse()
    {
        var tracker = new PresenceTracker();
        Assert.False(tracker.IsOnline("user1"));
    }

    [Fact]
    public void GetOnlineUsers_ReturnsOnlyOnlineUsers()
    {
        var tracker = new PresenceTracker();
        tracker.UserConnected("user1", "conn1");
        tracker.UserConnected("user3", "conn3");

        var result = tracker.GetOnlineUsers(new[] { "user1", "user2", "user3" });

        Assert.Equal(2, result.Length);
        Assert.Contains("user1", result);
        Assert.Contains("user3", result);
        Assert.DoesNotContain("user2", result);
    }
}
