using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;

namespace SafeVault;

public sealed record ValidatedUserInput(string Username, string Email);

public static class InputValidator
{
    private static readonly Regex UsernamePattern = new("^[A-Za-z0-9_-]{3,32}$", RegexOptions.CultureInvariant);
    private static readonly Regex EmailPattern = new("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$", RegexOptions.CultureInvariant);

    public static bool TryValidateUserInput(
        string? username,
        string? email,
        out ValidatedUserInput? validatedInput,
        out IReadOnlyList<string> errors)
    {
        var validationErrors = new List<string>();
        var normalizedUsername = Normalize(username);
        var normalizedEmail = Normalize(email);

        if (normalizedUsername is null || !UsernamePattern.IsMatch(normalizedUsername))
        {
            validationErrors.Add("Username must be 3-32 characters and contain only letters, numbers, '_' or '-'.");
        }

        if (normalizedEmail is null || !EmailPattern.IsMatch(normalizedEmail) || !IsValidEmail(normalizedEmail))
        {
            validationErrors.Add("Email must be a valid email address.");
        }

        if (validationErrors.Count > 0)
        {
            validatedInput = null;
            errors = validationErrors;
            return false;
        }

        validatedInput = new ValidatedUserInput(normalizedUsername!, normalizedEmail!);
        errors = Array.Empty<string>();
        return true;
    }

    public static string EncodeForHtml(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return WebUtility.HtmlEncode(value);
    }

    private static string? Normalize(string? value)
    {
        if (value is null || value.Any(char.IsControl))
        {
            return null;
        }

        var normalized = value.Trim();
        return normalized.Length == 0 ? null : normalized;
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            var parsed = new MailAddress(email);
            return string.Equals(parsed.Address, email, StringComparison.OrdinalIgnoreCase);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
