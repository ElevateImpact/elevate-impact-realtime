namespace ElevateRealtime.Config;

public static class DatabaseConfig
{
    /// <summary>
    /// Converts a Railway-style postgres:// URI to an Npgsql connection string.
    /// Handles both postgres:// and postgresql:// prefixes.
    /// </summary>
    public static string ParseRailwayConnectionString(string uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
            throw new ArgumentException("Database URI cannot be empty", nameof(uri));

        // Normalize prefix
        if (uri.StartsWith("postgresql://"))
            uri = "postgres://" + uri["postgresql://".Length..];

        if (!uri.StartsWith("postgres://"))
            throw new ArgumentException("Database URI must start with postgres:// or postgresql://", nameof(uri));

        var parsed = new Uri(uri.Replace("postgres://", "http://"));
        var userInfo = parsed.UserInfo.Split(':', 2);

        var host = parsed.Host;
        var port = parsed.Port > 0 ? parsed.Port : 5432;
        var database = parsed.AbsolutePath.TrimStart('/');
        var username = Uri.UnescapeDataString(userInfo[0]);
        var password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : "";

        return $"Host={host};Port={port};Database={database};Username={username};Password={password};SSL Mode=Require;Trust Server Certificate=true";
    }
}
