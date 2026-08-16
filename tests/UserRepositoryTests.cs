using Microsoft.Data.Sqlite;
using NUnit.Framework;

namespace SafeVault.Tests;

[TestFixture]
public sealed class UserRepositoryTests
{
    [TestCase("' OR 1=1 --")]
    [TestCase("safe_user' OR '1'='1")]
    [TestCase("safe_user'; DROP TABLE Users; --")]
    public async Task FindByUsernameAsync_TreatsSqlInjectionPayloadAsLiteral(string maliciousUsername)
    {
        var connectionString = $"Data Source=file:test-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await CreateUsersTableAsync(connection);
        await InsertUserAsync(connection, "safe_user", "safe@example.com");

        var repository = new UserRepository(connectionString);
        var result = await repository.FindByUsernameAsync(maliciousUsername);

        Assert.That(result, Is.Null);
        Assert.That(await CountUsersAsync(connection), Is.EqualTo(1));
    }

    [Test]
    public async Task FindByUsernameAsync_ReturnsMatchingUser()
    {
        var connectionString = $"Data Source=file:test-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await CreateUsersTableAsync(connection);
        await InsertUserAsync(connection, "safe_user", "safe@example.com");

        var repository = new UserRepository(connectionString);
        var result = await repository.FindByUsernameAsync("safe_user");

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Username, Is.EqualTo("safe_user"));
        Assert.That(result.Email, Is.EqualTo("safe@example.com"));
    }

    [TestCase("' OR '1'='1")]
    [TestCase("user@example.com' --")]
    public async Task FindByEmailAsync_TreatsSqlInjectionPayloadAsLiteral(string maliciousEmail)
    {
        var connectionString = $"Data Source=file:test-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await CreateUsersTableAsync(connection);
        await InsertUserAsync(connection, "safe_user", "safe@example.com");

        var repository = new UserRepository(connectionString);
        var result = await repository.FindByEmailAsync(maliciousEmail);

        Assert.That(result, Is.Null);
        Assert.That(await CountUsersAsync(connection), Is.EqualTo(1));
    }

    private static async Task CreateUsersTableAsync(SqliteConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL UNIQUE
            );
            """;
        await command.ExecuteNonQueryAsync();
    }

    private static async Task InsertUserAsync(SqliteConnection connection, string username, string email)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO Users (Username, Email) VALUES ($username, $email);";
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<long> CountUsersAsync(SqliteConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM Users;";
        return (long)(await command.ExecuteScalarAsync())!;
    }
}
