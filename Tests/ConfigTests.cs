using Xunit;
using ElevateRealtime.Config;

namespace ElevateRealtime.Tests;

public class ConfigTests
{
    [Fact]
    public void ParseRailwayConnectionString_PostgresPrefix_ReturnsValidConnectionString()
    {
        var uri = "postgres://user:pass@host:5432/mydb";
        var result = DatabaseConfig.ParseRailwayConnectionString(uri);

        Assert.Contains("Host=host", result);
        Assert.Contains("Port=5432", result);
        Assert.Contains("Database=mydb", result);
        Assert.Contains("Username=user", result);
        Assert.Contains("Password=pass", result);
    }

    [Fact]
    public void ParseRailwayConnectionString_PostgresqlPrefix_ReturnsValidConnectionString()
    {
        var uri = "postgresql://admin:secret@db.example.com:5433/proddb";
        var result = DatabaseConfig.ParseRailwayConnectionString(uri);

        Assert.Contains("Host=db.example.com", result);
        Assert.Contains("Port=5433", result);
        Assert.Contains("Database=proddb", result);
        Assert.Contains("Username=admin", result);
        Assert.Contains("Password=secret", result);
    }

    [Fact]
    public void ParseRailwayConnectionString_UrlEncodedPassword_DecodesCorrectly()
    {
        var uri = "postgres://user:p%40ss%23word@host:5432/db";
        var result = DatabaseConfig.ParseRailwayConnectionString(uri);

        Assert.Contains("Password=p@ss#word", result);
    }

    [Fact]
    public void ParseRailwayConnectionString_EmptyUri_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => DatabaseConfig.ParseRailwayConnectionString(""));
    }

    [Fact]
    public void ParseRailwayConnectionString_InvalidPrefix_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => DatabaseConfig.ParseRailwayConnectionString("mysql://user:pass@host/db"));
    }
}
