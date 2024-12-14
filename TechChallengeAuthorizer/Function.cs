using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace TechChallengeAuthorizer;

public class Function
{
    private readonly string SecretKey = Environment.GetEnvironmentVariable("SECRET_KEY") ?? string.Empty;

    public APIGatewayCustomAuthorizerV2SimpleResponse FunctionHandler(APIGatewayCustomAuthorizerV2Request request, ILambdaContext context)
    {
        try
        {
            context.Logger.LogLine($"APIGatewayCustomAuthorizerV2Request: {JsonSerializer.Serialize(request)}");

            ValidateToken(request.Headers.GetValueOrDefault("authorization"), context);
            return new APIGatewayCustomAuthorizerV2SimpleResponse
            {
                IsAuthorized = true
            };
        }
        catch (Exception ex)
        {
            context.Logger.LogLine($"Token validation failed: {ex.Message}");
            return new APIGatewayCustomAuthorizerV2SimpleResponse
            {
                IsAuthorized = false
            };
        } 
    }

    public ClaimsPrincipal? ValidateToken(string? token, ILambdaContext context)
    {
        if (string.IsNullOrEmpty(SecretKey))
        {
            throw new Exception("SecretKey is missing");
        }

        if (string.IsNullOrEmpty(token))
        {
            throw new Exception("Authorization token is missing");
        }

        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = token.Substring("Bearer ".Length).Trim();
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(SecretKey);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true, 
            ClockSkew = TimeSpan.Zero
        };

        var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

        if (validatedToken is JwtSecurityToken jwtToken &&
            jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase))
        {
            context.Logger.LogLine("Token successfully validated.");
            return principal;
        }
        else
        {
            throw new SecurityTokenException("Invalid token signature or algorithm.");
        }
    }
}
