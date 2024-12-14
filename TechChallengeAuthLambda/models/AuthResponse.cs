namespace TechChallengeAuthLambda.models;

public class AuthResponse
{
    public string? Token { get; set; }
    public string Message { get; set; }
    public bool IsAuthenticated { get; set; }
}
