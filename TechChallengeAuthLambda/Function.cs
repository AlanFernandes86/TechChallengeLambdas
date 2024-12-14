using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using TechChallengeAuthLambda.models;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace TechChallengeAuthLambda;

public class Function
{
    private const string SecretKey = "ffdf0228-bbee-4ba0-bcfc-6a712021219b"; // Use a chave segura, como do Secrets Manager
    private const string Issuer = "https://your-issuer.com"; // Atualize com o seu domínio
    private const string Audience = "your-audience"; // Atualize com o seu público-alvo

    /// <summary>
    /// A simple function that takes a string and does a ToUpper
    /// </summary>
    /// <param name="input">The event for the Lambda function handler to process.</param>
    /// <param name="context">The ILambdaContext that provides methods for logging and describing the Lambda environment.</param>
    /// <returns></returns>
    public APIGatewayProxyResponse FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
    {
        try
        {
            var authRequest = JsonSerializer.Deserialize<AuthRequest>(request.Body);

            if (!IsValidUser(authRequest.Username, authRequest.Password))
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = 401,
                    Body = JsonSerializer.Serialize(new { message = "Invalid username or password" })
                };
            }

            var token = GenerateJwtToken(authRequest.Username);

            return new APIGatewayProxyResponse
            {
                StatusCode = 200,
                Body = JsonSerializer.Serialize(new AuthResponse { 
                   Token = token,
                   Message = "Authenticated",
                   IsAuthenticated = true
                })
            };
        }
        catch (Exception ex)
        {
            context.Logger.LogError(ex.Message);
            return new APIGatewayProxyResponse
            {
                StatusCode = 500,
                Body = JsonSerializer.Serialize(new AuthResponse
                {
                    Token = string.Empty,
                    Message = "Internal Server Error",
                    IsAuthenticated = false
                })
            };
        }
    }

    private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, "User"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(3),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private bool IsValidUser(string username, string password)
    {
        // Substitua por lógica real de autenticação (e.g., banco de dados)
        return username == "admin" && password == "password123";
    }
}
