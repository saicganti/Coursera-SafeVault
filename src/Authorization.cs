namespace SafeVault;

public enum UserRole
{
    User,
    Admin
}

public static class RoleAuthorization
{
    public static bool CanAccessAdminDashboard(AuthenticatedUser? user)
    {
        return user is not null && user.Role == UserRole.Admin;
    }
}
