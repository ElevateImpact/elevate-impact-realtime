namespace ElevateRealtime.Hubs;

public interface IElevateHubClient
{
    Task MessageReceived(object payload);
    Task MessageDeleted(object payload);
    Task ReadReceiptReceived(object payload);
    Task ConversationUpdated(object payload);
    Task TypingIndicatorReceived(object payload);
    Task UserPresenceChanged(object payload);
    Task SamThinkingStarted(object payload);
    Task SamThinkingStopped(object payload);
}
