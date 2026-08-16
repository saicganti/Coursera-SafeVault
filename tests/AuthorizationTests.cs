using NUnit.Framework;

namespace SafeVault.Tests;

[TestFixture]
public sealed class AuthorizationTests
{
    [Test]
    public void CanAccessAdminDashboard_AllowsAdmin()
    {
        var user = new AuthenticatedUser(1, "administrator", UserRole.Admin);

        Assert.That(RoleAuthorization.CanAccessAdminDashboard(user), Is.True);
    }

    [Test]
    public void CanAccessAdminDashboard_DeniesRegularUser()
    {
        var user = new AuthenticatedUser(2, "safe_user", UserRole.User);

        Assert.That(RoleAuthorization.CanAccessAdminDashboard(user), Is.False);
    }

    [Test]
    public void CanAccessAdminDashboard_DeniesUnauthenticatedUser()
    {
        Assert.That(RoleAuthorization.CanAccessAdminDashboard(null), Is.False);
    }
}
