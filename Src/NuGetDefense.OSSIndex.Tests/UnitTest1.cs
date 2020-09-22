using NUnit.Framework;

namespace NuGetDefense.OSSIndex.Tests
{
    public class Tests
    {

        private readonly NuGetPackage[] InvulnerablePackages = { new NuGetPackage()
            {
                Id = "System.Text.Json",
                Version = "4.7.0"
            },
            new NuGetPackage()
            {
                Id = "Microsoft.AspNetCore.Blazor",
                Version = "3.0.0-preview9.19465.2"
            },
            new NuGetPackage()
            {
                Id = "Microsoft.AspNetCore.Blazor.Build",
                Version = "3.0.0-preview9.19465.2"
            },
            new NuGetPackage()
            {
                Id = "Microsoft.AspNetCore.Blazor.HttpClient",
                Version = "3.0.0-preview9.19465.2"
            },
            new NuGetPackage()
            {
                Id = "Microsoft.AspNetCore.Blazor.DevServer",
                Version = "3.0.0-preview9.19465.2"
            }
        };
            
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void PackagesWithoutVulnerabilities()
        {
            var scanner = new Scanner("somefile", true, username: "", passToken: "");
            var vulns = scanner.GetVulnerabilitiesForPackages(InvulnerablePackages);
            Assert.True(vulns.Count == 0);
        }
    }
}