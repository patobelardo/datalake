# PoC - Data Lake Gen 2 c# access

## Authentication using certificates

1- Created the certificate

````powershell
Write-Host "Creating the client application (daemon-console)"
$certificate=New-SelfSignedCertificate -Subject CN=DaemonConsoleCert `
                                        -CertStoreLocation "Cert:\CurrentUser\My" `
                                        -KeyExportPolicy Exportable `
                                        -KeySpec Signature
$certKeyId = [Guid]::NewGuid()
$certBase64Value = [System.Convert]::ToBase64String($certificate.GetRawCertData())
$certBase64Thumbprint = [System.Convert]::ToBase64String($certificate.GetCertHash())

$pwd = ConvertTo-SecureString -String 'passw0rd!' -Force -AsPlainText
$path = 'Cert:\CurrentUser\My\' + $certificate.thumbprint 
Export-PfxCertificate -cert $path -FilePath c:\temp\cert.pfx -Password $pwd
Export-Certificate -Cert $path -FilePath c:\temp\cert.cer -Type CERT
````

2- Upload .cer file to the AAD Application (App Registrations)
3- Reference it from code

````csharp
 X509Certificate2 certificate = ReadCertificate(config["CertificateName"]);
app = ConfidentialClientApplicationBuilder.Create(config["ClientId"])
    .WithCertificate(certificate)
    .WithAuthority(authority)
    .Build();
````

## Access to Data Lake Gen2 using REST APIs

1- Get the token

````csharp
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
````

2- Add headers and token at httpClient

````csharp
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
````

3- Call APIs

````csharp
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("List of filesystems");

var url = $"https://{storageName}.dfs.core.windows.net/?resource=account";

var response = await httpClient.GetAsync(url);
await processResult(response);
````


References:
- [QuickStart of MSAL](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-v2-netcore-daemon)
- [API References](https://docs.microsoft.com/en-us/rest/api/storageservices/data-lake-storage-gen2)
- [Custom/Community SDK](https://github.com/magicheron/AzureDataLakeGen2-SDK)
- [Multi-protocol access on Azure Data Lake Storage(preview)](https://docs.microsoft.com/en-us/azure/storage/blobs/data-lake-storage-multi-protocol-access)
- [Known issues with Azure Data Lake Storage Gen2](https://docs.microsoft.com/en-us/azure/storage/blobs/data-lake-storage-known-issues)

