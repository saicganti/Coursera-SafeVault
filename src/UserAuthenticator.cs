using BCrypt.Net;

namespace SafeVault;

public sealed record AuthenticatedUser(long UserId, string Username, UserRole Role);

public sealed class UserAuthenticator
{
    private const string DummyPasswordHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
    private readonly UserRepository userRepository;

    public UserAuthenticator(UserRepository userRepository)
    {
        this.userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
    }

    public async Task<AuthenticatedUser?> AuthenticateAsync(
        string? username,
        string? password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            return null;
        }

        var credential = await userRepository.FindCredentialByUsernameAsync(username, cancellationToken);
        if (credential is null)
        {
            BCrypt.Net.BCrypt.Verify(password, DummyPasswordHash);
            return null;
        }

        if (!BCrypt.Net.BCrypt.Verify(password, credential.PasswordHash))
        {
            return null;
        }

        return new AuthenticatedUser(credential.UserId, credential.Username, credential.Role);
    }
}
