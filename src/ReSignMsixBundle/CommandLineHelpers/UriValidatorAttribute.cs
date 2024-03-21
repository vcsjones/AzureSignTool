namespace ReSignMsixBundle.CommandLineHelpers;

internal class UriValidatorAttribute() : ValidationAttribute("The value for '{0}' is not a valid HTTP or HTTPS URI.")
{
    private static readonly string[] ValidSchemes = { Uri.UriSchemeHttp, Uri.UriSchemeHttps };

    protected override ValidationResult IsValid(object? value, ValidationContext context)
    {
        return value is null || (Uri.TryCreate(value.ToString(), UriKind.Absolute, out var uri) && ValidSchemes.Contains(uri.Scheme))
            ? ValidationResult.Success!
            : new ValidationResult(FormatErrorMessage(context.DisplayName));
    }
}
