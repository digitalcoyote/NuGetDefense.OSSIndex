using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using NuGetDefense.Core;

namespace NuGetDefense.OSSIndex
{
    /// <summary>
    ///     Handles interaction with the OSS Index Rest API (https://ossindex.sonatype.org/doc/rest)
    /// </summary>
    public class Scanner
    {
        private const string ResponseContentType = "application/vnd.ossindex.component-report.v1+json";
        private const string RequestContentType = "application/vnd.ossindex.component-report-request.v1+json";
        private readonly string UserAgentString;


        public Scanner(string nugetFile, bool breakIfCannotRun = false, string userAgentString = @"NuGetDefense.OSSIndex/1.0.1.5 (https://github.com/digitalcoyote/NuGetDefense.OSSIndex/blob/master/README.md)")
        {
            NugetFile = nugetFile;
            BreakIfCannotRun = breakIfCannotRun;
            UserAgentString = userAgentString;
        }

        private string NugetFile { get; }
        private bool BreakIfCannotRun { get; }

        /// <summary>
        ///     Gets vulnerabilities for a single NuGet Package.
        /// </summary>
        /// <param name="pkg">NuGetPackage to check</param>
        /// <returns></returns>
        private async Task<ComponentReport> GetReportForPackageAsync(NuGetPackage pkg)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(ResponseContentType));
                var response =
                    await client.GetStringAsync(
                        $"https://ossindex.sonatype.org/api/v3/component-report/{pkg.PackageUrl}");
                return JsonSerializer.Deserialize<ComponentReport>(response, new JsonSerializerOptions());
            }
        }

        /// <summary>
        ///     Gets Vulnerabilities for a set of NuGet Packages
        /// </summary>
        /// <param name="pkgs"> Packages to Check</param>
        /// <returns></returns>
        private async Task<ComponentReport[]> GetReportsForPackagesAsync(NuGetPackage[] pkgs)
        {
            using var client = new HttpClient();
            var content = JsonSerializer.Serialize(new ComponentReportRequest
                {coordinates = pkgs.Select(p => p.PackageUrl).ToArray()});
            client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgentString);
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(ResponseContentType));
            try
            {
                var response = await client
                    .PostAsync("https://ossindex.sonatype.org/api/v3/component-report",
                        new StringContent(content, Encoding.UTF8, RequestContentType));
                var jsonResponse = response.Content.ReadAsStreamAsync().Result;
                try
                {
                    return await JsonSerializer.DeserializeAsync<ComponentReport[]>(jsonResponse,
                        new JsonSerializerOptions());
                }
                catch
                {
                    using var ms = new MemoryStream();
                    await jsonResponse.CopyToAsync(ms);
                    var str = "No response";

                    if (ms.Length > 0)
                        str = Encoding.Default.GetString(ms.ToArray());

                    Console.WriteLine($"Error Reading OSSIndex Response: '{str}'");
                    throw;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: '{e}'");
                throw;
            }
        }

        /// <summary>
        ///     Gets vulnerabilities for a single NuGet Package
        /// </summary>
        /// <param name="pkg">NuGetPAckage to check</param>
        /// <returns></returns>
        public ComponentReportVulnerability[] GetVulnerabilitiesForPackage(NuGetPackage pkg)
        {
            return GetReportForPackageAsync(pkg).Result.Vulnerabilities;
        }

        /// <summary>
        ///     Gets Vulnerabilities for a set of NuGet Packages
        /// </summary>
        /// <param name="pkgs"> Packages to Check</param>
        /// <returns></returns>
        public Dictionary<string, Dictionary<string, Vulnerability>> GetVulnerabilitiesForPackages(
            NuGetPackage[] pkgs,
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict =
                null)
        {
            try
            {
                var reports = GetReportsForPackagesAsync(pkgs).Result
                    .Where(report => report.Vulnerabilities.Length > 0);
                vulnDict ??= new Dictionary<string, Dictionary<string, Vulnerability>>();
                foreach (var report in reports)
                {
                    var pkgId = pkgs.First(p => p.PackageUrl == report.Coordinates).Id;
                    if (!vulnDict.ContainsKey(pkgId)) vulnDict.Add(pkgId, new Dictionary<string, Vulnerability>());
                    foreach (var vulnerability in report.Vulnerabilities)
                        vulnDict[pkgId].Add(vulnerability.Cve ?? $"OSS Index ID: {vulnerability.Id}",
                            vulnerability.ToVulnerability());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(
                    $"{NugetFile} : {(BreakIfCannotRun ? "Error" : "Warning")} : NuGetDefense : OSS Index scan failed with exception: {e}");
            }

            return vulnDict;
        }
    }
}