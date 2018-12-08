using System;
using System.ComponentModel.DataAnnotations;

namespace AzureSignTool
{
    internal class UriValidatorAttribute : ValidationAttribute
    {
        public UriValidatorAttribute() : base("The value for '{0}' is not a valid HTTP or HTTPS URI.")
        {
        }

        protected override ValidationResult IsValid(object value, ValidationContext context)
        {
            if (value is null)
            {
                return ValidationResult.Success;
            }
            if (Uri.TryCreate(value.ToString(), UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            {
                return ValidationResult.Success;
            }
            return new ValidationResult(FormatErrorMessage(context.DisplayName));
        }
    }

    internal class MinValueAttribute : ValidationAttribute
    {
        public int MinValue { get; }

        public MinValueAttribute(int minValue) : base($"The value for '{{0}}' does not meet the minimum value {minValue}.")
        {
            MinValue = minValue;
        }

        protected override ValidationResult IsValid(object value, ValidationContext context)
        {
            switch (value)
            {
                case null:
                    return ValidationResult.Success;
                case int i when i >= MinValue:
                    return ValidationResult.Success;
                default:
                    return new ValidationResult(FormatErrorMessage(context.DisplayName));
            }
        }
    }
}
