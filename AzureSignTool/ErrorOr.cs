using System;

namespace AzureSignTool
{
    public class ErrorOr<TValue>
    {
        private readonly TValue _value;
        private readonly Exception _error;

        private ErrorOr(TValue value) => _value = value;

        private ErrorOr(Exception ex) => _error = ex;

        public static implicit operator ErrorOr<TValue>(TValue value) => new ErrorOr<TValue>(value);
        public static implicit operator ErrorOr<TValue>(Exception ex) => new ErrorOr<TValue>(ex);

        public class Ok : ErrorOr<TValue>
        {
            private Ok(TValue value) : base(value)
            {
            }

            public TValue Value => _value;
        }

        public class Err : ErrorOr<TValue>
        {
            private Err(Exception ex) : base(ex)
            {
            }

            public Exception Error => _error;
        }
    }
}
