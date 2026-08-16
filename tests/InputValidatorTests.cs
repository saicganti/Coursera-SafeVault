using NUnit.Framework;

namespace SafeVault.Tests;

[TestFixture]
public sealed class InputValidatorTests
{
    [TestCase("<script>alert('xss')</script>")]
    [TestCase("<img src=x onerror=alert('xss')>")]
    [TestCase("<svg/onload=alert('xss')>")]
    public void TryValidateUserInput_RejectsMarkupPayload(string maliciousUsername)
    {
        var isValid = InputValidator.TryValidateUserInput(
            maliciousUsername,
            "user@example.com",
            out _,
            out var errors);

        Assert.That(isValid, Is.False);
        Assert.That(errors, Is.Not.Empty);
    }

    [Test]
    public void TryValidateUserInput_RejectsControlCharacters()
    {
        var isValid = InputValidator.TryValidateUserInput(
            "safe\nuser",
            "user@example.com",
            out _,
            out var errors);

        Assert.That(isValid, Is.False);
        Assert.That(errors, Is.Not.Empty);
    }

    [Test]
    public void TryValidateUserInput_RejectsMalformedEmail()
    {
        var isValid = InputValidator.TryValidateUserInput(
            "safe_user",
            "user@example.com<script>",
            out _,
            out var errors);

        Assert.That(isValid, Is.False);
        Assert.That(errors, Is.Not.Empty);
    }

    [Test]
    public void TryValidateUserInput_RejectsScriptInEmail()
    {
        var isValid = InputValidator.TryValidateUserInput(
            "safe_user",
            "<script>alert('xss')</script>@example.com",
            out _,
            out var errors);

        Assert.That(isValid, Is.False);
        Assert.That(errors, Is.Not.Empty);
    }

    [Test]
    public void EncodeForHtml_EncodesMarkup()
    {
        var encoded = InputValidator.EncodeForHtml("<script>alert(1)</script>");

        Assert.That(encoded, Is.EqualTo("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    [Test]
    public void EncodeForHtml_EncodesAttributeBreakingCharacters()
    {
        var encoded = InputValidator.EncodeForHtml("\"'&<>");

        Assert.That(encoded, Is.EqualTo("&quot;&#39;&amp;&lt;&gt;"));
    }

    [Test]
    public void TryValidateUserInput_NormalizesValidValues()
    {
        var isValid = InputValidator.TryValidateUserInput(
            "  safe_user  ",
            " USER@EXAMPLE.COM ",
            out var validatedInput,
            out var errors);

        Assert.That(isValid, Is.True);
        Assert.That(errors, Is.Empty);
        Assert.That(validatedInput!.Username, Is.EqualTo("safe_user"));
        Assert.That(validatedInput.Email, Is.EqualTo("USER@EXAMPLE.COM"));
    }
}
