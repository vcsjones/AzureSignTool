using System.Diagnostics;
using System.Text;

namespace ReSignMsixBundle.BusinessLogic;

internal class ProcessAsyncHelper : IDisposable
{
    private readonly Process _process = new();

    public void Dispose()
    {
        _process.Dispose();
    }

    /// <summary>Executes the 'shell' command.</summary>
    /// <param name="command">The command.</param>
    /// <param name="arguments">The arguments.</param>
    /// <param name="timeout">The timeout in milliseconds.</param>
    /// <returns>A ProcessResult.</returns>
    public async Task<ProcessResult> ExecuteShellCommandAsync(string command, string arguments, int timeout)
    {
        Debug.Assert(!string.IsNullOrEmpty(command));
        Debug.Assert(timeout > 0);

        _process.StartInfo.FileName = command;
        _process.StartInfo.Arguments = arguments;
        _process.StartInfo.UseShellExecute = false;
        _process.StartInfo.RedirectStandardInput = true;
        _process.StartInfo.RedirectStandardOutput = true;
        _process.StartInfo.RedirectStandardError = true;
        _process.StartInfo.CreateNoWindow = true;

        var outputBuilder = new StringBuilder();
        var outputCloseEvent = new TaskCompletionSource<bool>();

        _process.OutputDataReceived += (_, eventArgs) =>
        {
            // If there is no data, the process has ended
            if (eventArgs.Data == null)
            {
                outputCloseEvent.SetResult(true);
            }
            else if (eventArgs.Data.Length > 0)
            {
                outputBuilder.AppendLine(eventArgs.Data);
            }
        };

        var errorBuilder = new StringBuilder();
        var errorCloseEvent = new TaskCompletionSource<bool>();

        _process.ErrorDataReceived += (_, eventArgs) =>
        {
            // If there is no data, the process has ended
            if (eventArgs.Data == null)
            {
                errorCloseEvent.SetResult(true);
            }
            else if (eventArgs.Data.Length > 0)
            {
                errorBuilder.AppendLine(eventArgs.Data);
            }
        };

        try
        {
            var isStarted = _process.Start();
            if (!isStarted)
            {
                return new ProcessResult(false, -1, "Not started");
            }
        }
        catch (Exception error)
        {
            // Usually this happens when the executable file is not found or is not executable
            return new ProcessResult(false, -1, error.Message);
        }

        // Read the output stream first and then wait, as deadlocks are possible
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();

        var waitForExitTask = Task.Run(() => _process.WaitForExit(timeout));

        // Create a task to wait for the process completion and the closure of all output streams
        var processTask = Task.WhenAll(waitForExitTask, outputCloseEvent.Task, errorCloseEvent.Task);

        // Wait for process to complete and then check that it did not happen by timeout
        var firstCompletedTask = await Task.WhenAny(Task.Delay(timeout), processTask);
        if (firstCompletedTask == processTask && await waitForExitTask)
        {
            return new ProcessResult(true, _process.ExitCode, GetOutput());
        }

        try
        {
            // Try to terminate the hanging process.
            _process.Kill();
        }
        catch
        {
            // pass
        }

        return new ProcessResult(false, -1, GetOutput());

        string GetOutput()
        {
            return $"{outputBuilder}{errorBuilder}".TrimEnd();
        }
    }

    public record struct ProcessResult(bool Completed, int ExitCode, string Output);
}
