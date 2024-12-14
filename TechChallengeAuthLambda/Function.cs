using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using TechChallengeAuthenticate.models;
using TechChallengeAuthLambda.models;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace TechChallengeAuthenticate;

public class Function
{
    private readonly string SecretKey = Environment.GetEnvironmentVariable("SECRET_KEY") ?? string.Empty;
    private readonly string Issuer = Environment.GetEnvironmentVariable("ISSUER") ?? string.Empty;
    private readonly string Audience = Environment.GetEnvironmentVariable("AUDIENCE") ?? string.Empty;

    private readonly AmazonDynamoDBClient _dynamoDbClient;

    public Function()
    {
        _dynamoDbClient = new AmazonDynamoDBClient();
    }

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
            if (SecretKey == string.Empty || Issuer == string.Empty || Audience == string.Empty)
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = JsonSerializer.Serialize(new AuthResponse
                    {
                        Token = string.Empty,
                        Message = "Internal Server Error - No Secrets Configured",
                        IsAuthenticated = false
                    })
                };
            }

            var authRequest = JsonSerializer.Deserialize<AuthRequest>(request.Body);
            var validUser = GetValidUser(authRequest.Username);

            if (validUser is null)
            {
                return new APIGatewayProxyResponse
                {
                    StatusCode = 401,
                    Body = JsonSerializer.Serialize(new AuthResponse
                    {
                        Token = string.Empty,
                        Message = "Invalid username or password.",
                        IsAuthenticated = false
                    })
                };
            }

            var token = GenerateJwtToken(validUser);

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
                    Message = $"Internal Server Error - {ex.Message}",
                    IsAuthenticated = false
                })
            };
        }
    }

    private string GenerateJwtToken(User user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Role, user.Group),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private User? GetValidUser(string username)
    {
        var queryRequest = new QueryRequest
        {
            TableName = "user",
            KeyConditionExpression = "cpf = :cpf",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                { ":cpf", new AttributeValue { S = username } }
            }
        };

        var result = _dynamoDbClient.QueryAsync(queryRequest).Result;
        var userItem = result.Items.FirstOrDefault();

        User? user = null;
        if (userItem != null)
        {
            user = new User
            {
                Cpf = userItem["cpf"].S,
                Name = userItem["name"].S,
                Email = userItem["email"].S,
                Group = userItem["group"].S,
                CreatedAt = DateTime.Parse(userItem["created_at"].S),
                UpdatedAt = DateTime.Parse(userItem["updated_at"].S)
            };
        }

        return user;
    }
}
