var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Insecure training example: appsettings.json contains a plainly visible demo payment key.
// It is an unusable placeholder, not a credential. Secure fix: inject a real secret from
// a secret manager, for example builder.Configuration["PaymentGateway:ApiKey"].

app.MapGet("/", () => Results.Ok(new
{
    service = "SentinelGate mock payments API",
    warning = "Local security-training demo. Do not use with real data or credentials."
}));

app.MapGet("/api/users", () =>
{
    // These are intentionally synthetic, invalid identifiers for the local demo only.
    // Real services should minimize, mask, encrypt, and strictly authorize personal data.
    // Secure fix example: return masked values such as "***********0000" and "******0000".
    return Results.Ok(new[]
    {
        new DemoUser("user-001", "Lerato Example", "0000000000000", "0000000000"),
        new DemoUser("user-002", "Sipho Sample", "1111111111111", "1111111111")
    });
});

app.MapGet("/api/transactions", () => Results.Ok(new[]
{
    new DemoTransaction("txn-1001", "user-001", 1250.00m, "ZAR", "completed"),
    new DemoTransaction("txn-1002", "user-002", 499.99m, "ZAR", "pending")
}));

app.MapGet("/api/transactions/{id}", (string id) =>
{
    // Insecure scanner-training pattern only; do not execute interpolated SQL:
    // var query = $"SELECT * FROM Transactions WHERE Id = '{id}'";
    // Secure fix: use a parameterized query, e.g.
    // command.CommandText = "SELECT * FROM Transactions WHERE Id = @id";
    // command.Parameters.AddWithValue("@id", id);
    var transaction = new[]
    {
        new DemoTransaction("txn-1001", "user-001", 1250.00m, "ZAR", "completed"),
        new DemoTransaction("txn-1002", "user-002", 499.99m, "ZAR", "pending")
    }.FirstOrDefault(candidate => candidate.Id == id);

    return transaction is null ? Results.NotFound() : Results.Ok(transaction);
})
.WithName("GetTransactionById")
.WithSummary("Look up a demo transaction by ID");

app.MapPost("/api/auth/login", (LoginRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { error = "Username and password are required." });
    }

    // Mock only: this endpoint does not authenticate users or issue a usable token.
    return Results.Ok(new { authenticated = true, token = "demo-token-not-for-use" });
});

app.Run();

internal sealed record DemoUser(string Id, string Name, string SouthAfricanIdNumber, string AccountNumber);
internal sealed record DemoTransaction(string Id, string UserId, decimal Amount, string Currency, string Status);
internal sealed record LoginRequest(string Username, string Password);
