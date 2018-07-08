using System.IO;
using System.Text;
using AzureSignTool;
using Xunit;

namespace AzureSignTool.Tests
{
    public class LoggerTests
    {
        [Fact]
        public void ShouldNotWriteToLogIfLevelAboveCurrentLevel()
        {
            var builder = new StringBuilder();
            var logger = new TextWriterLogger(new StringWriter(builder));
            logger.Level = LogLevel.Normal;

            logger.Log("Hello don't log me.", LogLevel.Verbose);
            Assert.Equal(0, builder.Length);
        }


        [Fact]
        public void ShouldWriteToLogIfLevelEqualToCurrentLevel()
        {
            var builder = new StringBuilder();
            var logger = new TextWriterLogger(new StringWriter(builder));
            logger.Level = LogLevel.Verbose;

            logger.Log("Hello log me.", LogLevel.Verbose);
            Assert.Contains("Hello log me.", builder.ToString());
        }

        [Fact]
        public void ShouldNestALogGroup()
        {
            var builder = new StringBuilder();
            var logger = new TextWriterLogger(new StringWriter(builder));

            var scoped1 = logger.Scoped();
            scoped1.Log("I am nested.");
            var scoped2 = logger.Scoped();
            scoped2.Log("I am also nested.");
            Assert.Contains("[1] I am nested.", builder.ToString());
            Assert.Contains("[2] I am also nested.", builder.ToString());
        }

        [Fact]
        public void ShouldNestWithinANestedLog()
        {
            var builder = new StringBuilder();
            var logger = new TextWriterLogger(new StringWriter(builder));

            var scoped1 = logger.Scoped();
            var scoped2 = logger.Scoped();
            var scoped11 = scoped1.Scoped();
            var scoped21 = scoped2.Scoped();
            var scoped22 = scoped2.Scoped();
            scoped1.Log("I am nested.");
            scoped11.Log("I am more nested.");
            scoped2.Log("Different nested scope.");
            scoped21.Log("21");
            scoped22.Log("22");
            var logs = builder.ToString();
            Assert.Contains("[1] I am nested.", logs);
            Assert.Contains("[2] Different nested scope.", logs);
            Assert.Contains("[1][1] I am more nested.", logs);
            Assert.Contains("[2][1] 21", logs);
            Assert.Contains("[2][2] 22", logs);
        }

        [Fact]
        public void ChildScopesInheritParentScopeLevel()
        {
            var builder = new StringBuilder();
            var logger = new TextWriterLogger(new StringWriter(builder));
            logger.Level = LogLevel.Quiet;
            var scoped = logger.Scoped();
            Assert.Equal(LogLevel.Quiet, scoped.Level);
        }
    }
}