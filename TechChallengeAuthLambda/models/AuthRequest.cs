﻿using System.Text.Json.Serialization;

namespace TechChallengeAuthLambda.models;

public class AuthRequest
{
    [JsonPropertyName("username")]
    public string Username { get; set; }

    [JsonPropertyName("password")]
    public string Password { get; set; }
}
