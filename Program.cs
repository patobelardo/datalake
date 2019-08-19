using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates; //Only import this if you are using certificate
using System.Threading.Tasks;
using System.Web;

namespace datalake
{
    class Program
    {
        private static IConfigurationRoot config;
        private static string storageName; 
        private static Uri authority;
        private static string token = string.Empty;
        private static HttpClient httpClient;
        static void Main(string[] args)
        {
            try
            {
                RunAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();
            }

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        private static async Task RunAsync()
        {
            getConfigurationSettings();

            // You can run this sample using ClientSecret or Certificate. The code will differ only when instantiating the IConfidentialClientApplication
            bool isUsingClientSecret = AppUsesClientSecret();

            // Even if this is a console application here, a daemon application is a confidential client application
            IConfidentialClientApplication app;

            if (isUsingClientSecret)
            {
                app = ConfidentialClientApplicationBuilder.Create(config["ClientId"])
                    .WithClientSecret(config["ClientSecret"])
                    .WithAuthority(new Uri(config["Authority"]))
                    .Build();
            }
        
            else
            {
                Console.WriteLine("Authenticating using certificates");
                X509Certificate2 certificate = ReadCertificate(config["CertificateName"]);
                app = ConfidentialClientApplicationBuilder.Create(config["ClientId"])
                    .WithCertificate(certificate)
                    .WithAuthority(authority)
                    .Build();
            }

            // With client credentials flows the scopes is ALWAYS of the shape "resource/.default", as the 
            // application permissions need to be set statically (in the portal or by PowerShell), and then granted by
            // a tenant administrator
            string[] scopes = new string[] { "https://storage.azure.com/.default" };

            AuthenticationResult result = null;
            try
            {
                result = await app.AcquireTokenForClient(scopes).ExecuteAsync();
                token = result.AccessToken;
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Token acquired");
                Console.ResetColor();
            }
            catch (MsalServiceException ex) when (ex.Message.Contains("AADSTS70011"))
            {
                // Invalid scope. The scope has to be of the form "https://resourceurl/.default"
                // Mitigation: change the scope to be as expected
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Scope provided is not supported");
                Console.ResetColor();
            }

            if (token != null)
            {
                initializeHttpClient();

                await ListFileSystemsAsync();

                var fsName = Guid.NewGuid().ToString();
                await CreateFilesystemAsync(fsName);

                var directoryName = Guid.NewGuid().ToString();
                await CreateDirectoryAsync(fsName, directoryName);

                string tmpFile = Path.GetTempFileName();
                string fileName = HttpUtility.UrlEncode(Path.GetFileName(tmpFile));
                File.WriteAllText(tmpFile, "Sample Contents");

                await CreateFileAsync(fsName, directoryName, fileName, new FileStream(tmpFile, FileMode.Open, FileAccess.Read));
            }
        }

        private static void initializeHttpClient()
        {
            httpClient = new HttpClient();
            var defaultRequetHeaders = httpClient.DefaultRequestHeaders;
            if (defaultRequetHeaders.Accept == null || !defaultRequetHeaders.Accept.Any(m => m.MediaType == "application/json"))
            {
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            }
            defaultRequetHeaders.Authorization = new AuthenticationHeaderValue("bearer", token);
            defaultRequetHeaders.Add("x-ms-version", "2018-11-09");
        }

        private static async Task ListFileSystemsAsync()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("List of filesystems");

            var url = $"https://{storageName}.dfs.core.windows.net/?resource=account";

            var response = await httpClient.GetAsync(url);
            await processResult(response);
        }
        private static async Task CreateFilesystemAsync(string filesystem)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Create a new filesystems: {filesystem} ");

            var url = $"https://{storageName}.dfs.core.windows.net/{filesystem}?resource=filesystem";

            var response = await httpClient.PutAsync(url, null);
            await processResult(response);
        }

        private static async Task CreateDirectoryAsync(string filesystem, string path)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Create a directory ({path}) at filesystem {filesystem}");

            var url = $"https://{storageName}.dfs.core.windows.net/{filesystem}/{path}?resource=directory";
            
            var response = await httpClient.PutAsync(url, null);
            await processResult(response);
        }

        private static async Task<bool> CreateEmptyFileAsync(string filesystem, string path, string fileName)
        {
            var resultValue = false;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Create an empty file name {fileName} at directory {path}, at filesystem {filesystem}");

            var url = $"https://{storageName}.dfs.core.windows.net/{filesystem}/{path}/{fileName}?resource=file";

            using (var tmpContent = new StreamContent(new MemoryStream()))
            {
                HttpRequestMessage newFileMsg = new HttpRequestMessage(HttpMethod.Put, url);
                newFileMsg.Content = tmpContent;
                var response = await httpClient.SendAsync(newFileMsg);
                await processResult(response);
                resultValue = response.IsSuccessStatusCode;
            }
            return resultValue;
        }

        private static async Task CreateFileAsync(string filesystem, string path, string fileName, Stream stream)
        {
            var operationResult = await CreateEmptyFileAsync(filesystem, path, fileName);
            if (operationResult)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Uploading {fileName} at directory {path}, at filesystem {filesystem}");
                using (var streamContent = new StreamContent(stream))
                {
                    //upload to the file buffer
                    var url = $"https://{storageName}.dfs.core.windows.net/{filesystem}/{path}/{fileName}?action=append&position=0";
                    
                    HttpRequestMessage msg = new HttpRequestMessage(new HttpMethod("PATCH"), url);
                    msg.Content = streamContent;
                    var response = await httpClient.SendAsync(msg);

                    //flush the buffer to commit the file
                    var flushUrl = $"https://{storageName}.dfs.core.windows.net/{filesystem}/{path}/{fileName}?action=flush&position={msg.Content.Headers.ContentLength}";
                    HttpRequestMessage flushMsg = new HttpRequestMessage(new HttpMethod("PATCH"), flushUrl);
                    response = await httpClient.SendAsync(flushMsg);

                    await processResult(response);
                }
            } 
        }

        private static async Task processResult(HttpResponseMessage response)
        {
            Console.WriteLine($"Response success: {response.IsSuccessStatusCode}");
            if (response.IsSuccessStatusCode)
            {
                string json = await response.Content.ReadAsStringAsync();
                JObject result = JsonConvert.DeserializeObject(json) as JObject;
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.WriteLine(result);
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Failed to call the Web Api: {response.StatusCode}");
                string content = await response.Content.ReadAsStringAsync();

                // Note that if you got reponse.Code == 403 and reponse.content.code == "Authorization_RequestDenied"
                // this is because the tenant admin as not granted consent for the application to call the Web API
                Console.WriteLine($"Content: {content}");
            }
            Console.ResetColor();
        }


        private static void getConfigurationSettings()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json");
            config = builder.Build();
            
            storageName = config["StorageAccountName"];

            authority = new Uri(String.Format(CultureInfo.InvariantCulture, "https://login.microsoftonline.com/{0}", config["Tenant"]));
        }



        /// <summary>
        /// Checks if the sample is configured for using ClientSecret or Certificate. This method is just for the sake of this sample.
        /// You won't need this verification in your production application since you will be authenticating in AAD using one mechanism only.
        /// </summary>
        /// <param name="config">Configuration from appsettings.json</param>
        /// <returns></returns>
        private static bool AppUsesClientSecret()
        {
            string clientSecretPlaceholderValue = "[Enter here a client secret for your application]";
            string certificatePlaceholderValue = "[Or instead of client secret: Enter here the name of a certificate (from the user cert store) as registered with your application]";

            if (!String.IsNullOrWhiteSpace(config["ClientSecret"]) && config["ClientSecret"] != clientSecretPlaceholderValue)
            {
                return true;
            }

            else if (!String.IsNullOrWhiteSpace(config["CertificateName"]) && config["CertificateName"] != certificatePlaceholderValue)
            {
                return false;
            }

            else
                throw new Exception("You must choose between using client secret or certificate. Please update appsettings.json file.");
        }

        private static X509Certificate2 ReadCertificate(string certificateName)
        {
            if (string.IsNullOrWhiteSpace(certificateName))
            {
                throw new ArgumentException("certificateName should not be empty. Please set the CertificateName setting in the appsettings.json", "certificateName");
            }
            X509Certificate2 cert = null;

            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = store.Certificates;

                // Find unexpired certificates.
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

                // From the collection of unexpired certificates, find the ones with the correct name.
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certificateName, false);

                // Return the first certificate in the collection, has the right name and is current.
                cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();
            }
            return cert;
        }

    }
}
