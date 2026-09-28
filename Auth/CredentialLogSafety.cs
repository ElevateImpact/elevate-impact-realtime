using System.Text.RegularExpressions;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace ElevateRealtime.Auth;

/// <summary>Keeps hub credentials (the access_token query) out of logs. See AGENTS.md §H-14 logging.</summary>
public static partial class CredentialLogSafety
{
    public const string Redacted = "[redacted]";

    /// <summary>The service's Serilog levels plus redaction; Program.cs and the tests share it.</summary>
    public static LoggerConfiguration Configure(LoggerConfiguration configuration) => configuration
        .MinimumLevel.Information()
        // Hosting's per-request "Request starting ...?access_token=..." line is Information.
        .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
        .Enrich.With(new RedactCredentialQueryEnricher());

    /// <summary>Replaces the value of access_token= / apiKey= in any string property.</summary>
    public static string Redact(string value)
        => CredentialQuery().Replace(value, match => $"{match.Groups[1].Value}={Redacted}");

    [GeneratedRegex("(access_token|apiKey)=[^&\\s\"]*", RegexOptions.IgnoreCase)]
    private static partial Regex CredentialQuery();

    private sealed class RedactCredentialQueryEnricher : ILogEventEnricher
    {
        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
        {
            foreach (var (name, value) in logEvent.Properties.ToArray())
            {
                if (value is ScalarValue { Value: string text } && CredentialQuery().IsMatch(text))
                    logEvent.AddOrUpdateProperty(new LogEventProperty(name, new ScalarValue(Redact(text))));
            }
        }
    }
}
