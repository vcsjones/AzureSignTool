using JetBrains.Annotations;

namespace ReSignMsixBundle;

internal sealed class ReSignMsixBundleApplication(CommandLineApplication current)
{
    [UsedImplicitly]
    public int OnExecute()
    {
        current.ShowHelp();
        return 1;
    }
}
