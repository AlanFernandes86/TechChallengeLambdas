namespace TechChallengeAuthenticate.models
{
    public class User
    {
        public string Cpf { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Group { get; set; }
        public DateTime CreatedAt { get; set; }

        public DateTime UpdatedAt { get; set; }
    }
}
