using BCrypt.Net;
using Microsoft.Data.Sqlite;
using NUnit.Framework;

namespace SafeVault.Tests;

[TestFixture]
public sealed class UserAuthenticatorTests
{
    [Test]
    public async Task AuthenticateAsync_ReturnsUserForValidCredentials()
    {
        var password = "CorrectHorseBatteryStaple!";
        await using var database = await CreateDatabaseAsync(password);

        var authenticator = new UserAuthenticator(new UserRepository(database.ConnectionString));
        var result = await authenticator.AuthenticateAsync("safe_user", password);

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Username, Is.EqualTo("safe_user"));
        Assert.That(result.UserId, Is.EqualTo(1));
        Assert.That(result.Role, Is.EqualTo(UserRole.User));
    }

    [Test]
    public async Task AuthenticateAsync_ReturnsAdminRoleForAdminCredentials()
    {
        const string password = "CorrectHorseBatteryStaple!";
        await using var database = await CreateDatabaseAsync(password, "admin");

        var authenticator = new UserAuthenticator(new UserRepository(database.ConnectionString));
        var result = await authenticator.AuthenticateAsync("safe_user", password);

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Role, Is.EqualTo(UserRole.Admin));
        Assert.That(RoleAuthorization.CanAccessAdminDashboard(result), Is.True);
    }

    [Test]
    public async Task AuthenticateAsync_RejectsWrongPassword()
    {
        await using var database = await CreateDatabaseAsync("CorrectHorseBatteryStaple!");

        var authenticator = new UserAuthenticator(new UserRepository(database.ConnectionString));
        var result = await authenticator.AuthenticateAsync("safe_user", "wrong-password");

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task AuthenticateAsync_RejectsUnknownUser()
    {
        await using var database = await CreateDatabaseAsync("CorrectHorseBatteryStaple!");

        var authenticator = new UserAuthenticator(new UserRepository(database.ConnectionString));
        var result = await authenticator.AuthenticateAsync("unknown_user", "CorrectHorseBatteryStaple!");

        Assert.That(result, Is.Null);
    }

    [TestCase(null, "password")]
    [TestCase("safe_user", null)]
    [TestCase("", "password")]
    [TestCase("safe_user", "")]
    public async Task AuthenticateAsync_RejectsMissingCredentials(string? username, string? password)
    {
        await using var database = await CreateDatabaseAsync("CorrectHorseBatteryStaple!");

        var authenticator = new UserAuthenticator(new UserRepository(database.ConnectionString));
        var result = await authenticator.AuthenticateAsync(username, password);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task CreateDatabase_StoresBcryptHashInsteadOfPlaintext()
    {
        const string password = "CorrectHorseBatteryStaple!";
        await using var database = await CreateDatabaseAsync(password);

        await using var command = database.CreateCommand();
        command.CommandText = "SELECT PasswordHash FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", "safe_user");
        var storedHash = (string)(await command.ExecuteScalarAsync())!;

        Assert.That(storedHash, Does.StartWith("$2"));
        Assert.That(storedHash, Is.Not.EqualTo(password));
        Assert.That(BCrypt.Net.BCrypt.Verify(password, storedHash), Is.True);
    }

    private static async Task<SqliteConnection> CreateDatabaseAsync(string password, string role = "user")
    {
        var connectionString = $"Data Source=file:test-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();

        await using (var createCommand = connection.CreateCommand())
        {
            createCommand.CommandText = """
                CREATE TABLE Users (
                    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username TEXT NOT NULL UNIQUE,
                    Email TEXT NOT NULL UNIQUE,
                    PasswordHash TEXT NOT NULL,
                    Role TEXT NOT NULL CHECK (Role IN ('admin', 'user'))
                );
                """;
            await createCommand.ExecuteNonQueryAsync();
        }

        await using (var insertCommand = connection.CreateCommand())
        {
            insertCommand.CommandText = """
                INSERT INTO Users (Username, Email, PasswordHash, Role)
                VALUES ($username, $email, $passwordHash, $role);
                """;
            insertCommand.Parameters.AddWithValue("$username", "safe_user");
            insertCommand.Parameters.AddWithValue("$email", "safe@example.com");
            insertCommand.Parameters.AddWithValue("$passwordHash", BCrypt.Net.BCrypt.HashPassword(password));
            insertCommand.Parameters.AddWithValue("$role", role);
            await insertCommand.ExecuteNonQueryAsync();
        }

        return connection;
    }
}
