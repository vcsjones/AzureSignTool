using McMaster.Extensions.CommandLineUtils;

namespace AzureSignTool
{
    internal sealed class SignApplication
    {
        private readonly CommandLineApplication _current;
        
        public SignApplication(CommandLineApplication current)
        {
            _current = current;
        }

        public int OnExecute()
        {
            _current.ShowHelp();
            return 1;
        }
    }
}
