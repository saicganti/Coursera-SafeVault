using Microsoft.Data.Sqlite;

namespace SafeVault;

public sealed record UserRecord(long UserId, string Username, string Email);
public sealed record UserCredential(long UserId, string Username, string PasswordHash, UserRole Role);

public sealed class UserRepository
{
    private readonly string connectionString;

    public UserRepository(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        this.connectionString = connectionString;
    }

    public async Task<UserRecord?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email
            FROM Users
            WHERE Username = $username
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$username", username);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new UserRecord(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetString(2));
    }

    public async Task<UserCredential?> FindCredentialByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, PasswordHash, Role
            FROM Users
            WHERE Username = $username
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$username", username);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var role = reader.GetString(3) switch
        {
            "admin" => UserRole.Admin,
            "user" => UserRole.User,
            _ => throw new InvalidOperationException("User has an unsupported role.")
        };

        return new UserCredential(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), role);
    }

    public async Task<UserRecord?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT UserID, Username, Email
            FROM Users
            WHERE Email = $email
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$email", email);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new UserRecord(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetString(2));
    }
}
