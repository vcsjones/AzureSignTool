using System;

namespace AzureSignTool
{
    public abstract class ErrorOr<TValue>
    {
        private readonly TValue _value;
        private readonly Exception _error;

        private ErrorOr(TValue value) => _value = value;

        private ErrorOr(Exception ex) => _error = ex;

        public static implicit operator ErrorOr<TValue>(TValue value) => new Ok(value);
        public static implicit operator ErrorOr<TValue>(Exception ex) => new Err(ex);

        public class Ok : ErrorOr<TValue>
        {
            internal Ok(TValue value) : base(value)
            {
            }

            public TValue Value => _value;
        }

        public class Err : ErrorOr<TValue>
        {
            internal Err(Exception ex) : base(ex)
            {
            }

            public Exception Error => _error;
        }
    }
}
