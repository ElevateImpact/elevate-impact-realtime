namespace ElevateRealtime.Models;

public class NotifyRequest
{
    public string EventType { get; set; } = string.Empty;
    public string Group { get; set; } = string.Empty;
    public object? Payload { get; set; }
    public string[]? UserGroups { get; set; }
}
