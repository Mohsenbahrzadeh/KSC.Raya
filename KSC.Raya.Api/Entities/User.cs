using Microsoft.AspNetCore.Identity;

namespace KSC.Raya.Api.Entities;

public class User : IdentityUser<Guid>
{
    public string FirstName { get; set; }

    public string LastName { get; set; }

    public bool Active { get; set; }

    public string PublicKey { get; set; }

    public string PrivateKey { get; set; }

    public string IV { get; set; }
    public string Salt { get; set; }

    public string Code { get; set; }

    public string FullName => $"{FirstName ?? ""} {LastName ?? ""} ";


}

