using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

// Command-line parameters: if a configuration file path is passed, use it; otherwise, default to "appsettings.json"
string configFileName = args.Length > 0 ? args[0] : "appsettings.json";
builder.Configuration.AddJsonFile(configFileName, optional: true, reloadOnChange: true);

// Configure logging with Debug level for more detailed logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Debug);
var logger = builder.Services.BuildServiceProvider().GetRequiredService<ILogger<Program>>();

logger.LogInformation("Version 3.0");

// Define base directory for the application
var baseDirectory = AppContext.BaseDirectory;

// Function to resolve relative paths to absolute paths based on baseDirectory
string ResolvePath(string? path)
{
    if (string.IsNullOrEmpty(path))
    {
        logger.LogError("Certificate path is null or empty.");
        throw new ArgumentNullException(nameof(path), "Path cannot be null or empty.");
    }

    // If the path is relative, convert it to absolute using baseDirectory
    return Path.IsPathRooted(path) ? path : Path.Combine(baseDirectory, path);
}

// Load default paths based on the base directory
string defaultServerCertificatePath = ResolvePath("webSrv.pfx");
string defaultCACertificatePath = ResolvePath("certCA.cer");
string defaultServerCertificatePassword = "qaz123";
X509RevocationMode defaultRevocationMode = X509RevocationMode.NoCheck;

// Log the base directory for debugging
logger.LogDebug("Base directory: {BaseDirectory}", baseDirectory);

// Load settings from the configuration file
string? serverCertificatePathConfig = builder.Configuration["Certificates:ServerCertificatePath"];
string? caCertificatePathConfig = builder.Configuration["Certificates:CACertificatePath"];

// Log the loaded configuration values for debugging
logger.LogDebug("ServerCertificatePath from config: {ServerCertificatePath}", serverCertificatePathConfig ?? "Not provided");
logger.LogDebug("CACertificatePath from config: {CACertificatePath}", caCertificatePathConfig ?? "Not provided");

// Resolve the paths using ResolvePath, and use defaults if the configuration value is null
var serverCertificatePath = ResolvePath(serverCertificatePathConfig ?? "webSrv.pfx");
var serverCertificatePassword = builder.Configuration["Certificates:ServerCertificatePassword"] ?? defaultServerCertificatePassword;
var caCertificatePath = ResolvePath(caCertificatePathConfig ?? "certCA.cer");

var revocationModeString = builder.Configuration["CertificateAuthentication:RevocationMode"];
var revocationMode = Enum.TryParse<X509RevocationMode>(revocationModeString, out var parsedRevocationMode)
    ? parsedRevocationMode
    : defaultRevocationMode;

// Load the root CA certificate
X509Certificate2? caCertificate = null;

try
{
    caCertificate = new X509Certificate2(caCertificatePath);
    logger.LogInformation("Successfully loaded CA certificate from {Path}", caCertificatePath);
}
catch (Exception ex)
{
    logger.LogError(ex, "Error loading CA certificate from {Path}", caCertificatePath);
    throw;
}

// Configure Kestrel to listen on HTTPS
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    // Listen on HTTPS port 443 with the server certificate
    serverOptions.ListenAnyIP(443, listenOptions =>
    {
        listenOptions.UseHttps(httpsOptions =>
        {
            try
            {
                httpsOptions.ServerCertificate = new X509Certificate2(serverCertificatePath, serverCertificatePassword);
                logger.LogInformation("Successfully loaded server certificate from {Path}", serverCertificatePath);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error loading server certificate from {Path}", serverCertificatePath);
                throw;
            }

            // Log the HTTPS connection establishment step
            httpsOptions.OnAuthenticate = (context, sslOptions) =>
            {
                logger.LogDebug("Establishing HTTPS connection. ClientCertificateMode: {Mode}", httpsOptions.ClientCertificateMode);
            };

            // Require client certificate for mTLS
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        });
    });
});

// Add authentication using CustomTrustStore for client certificate validation
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        // Use CustomRootTrust to validate client certificates only through your CA
        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        options.CustomTrustStore.Add(caCertificate); // Add root CA certificate to CustomTrustStore

        // Set revocation check mode from configuration
        options.RevocationMode = revocationMode;

        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var clientCert = context.ClientCertificate;
                logger.LogInformation("Client certificate validated. Subject: {Subject}, Issuer: {Issuer}", clientCert.Subject, clientCert.Issuer);

                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer),
                    new Claim(ClaimTypes.Name, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer)
                };

                context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                context.Success(); // Validation successful
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                logger.LogError("Client certificate authentication failed: {Error}", context.Exception.Message);
                context.Fail("Invalid certificate"); // Handle authentication failure
                return Task.CompletedTask;
            }
        };
    });

// Add authorization services (if used)
builder.Services.AddAuthorization();

var app = builder.Build();

// Enable authentication
app.UseAuthentication();

// Enable routing
app.UseRouting();

// Enable authorization
app.UseAuthorization();  // This call is needed to support authorization

// Simple endpoint for testing, displays all client certificate information
app.MapGet("/", (HttpContext context) =>
{
    var clientCertificate = context.Connection.ClientCertificate;

    if (clientCertificate == null)
    {
        logger.LogError("No client certificate provided.");
        return Results.BadRequest("No client certificate provided.");
    }

    var certInfo = new StringBuilder();
    certInfo.AppendLine($"Subject: {clientCertificate.Subject}");
    certInfo.AppendLine($"Issuer: {clientCertificate.Issuer}");
    certInfo.AppendLine($"Thumbprint: {clientCertificate.Thumbprint}");
    certInfo.AppendLine($"NotBefore: {clientCertificate.NotBefore}");
    certInfo.AppendLine($"NotAfter: {clientCertificate.NotAfter}");
    certInfo.AppendLine($"Serial Number: {clientCertificate.SerialNumber}");
    certInfo.AppendLine($"Version: {clientCertificate.Version}");
    certInfo.AppendLine($"Signature Algorithm: {clientCertificate.SignatureAlgorithm.FriendlyName}");

    if (clientCertificate.Extensions != null)
    {
        certInfo.AppendLine("Extensions:");
        foreach (var extension in clientCertificate.Extensions)
        {
            certInfo.AppendLine($"  {extension.Oid.FriendlyName} ({extension.Oid.Value}): {extension.Format(true)}");
        }
    }

    return Results.Text(certInfo.ToString());
})
.RequireAuthorization(); // Apply authorization to all requests

app.Run();
