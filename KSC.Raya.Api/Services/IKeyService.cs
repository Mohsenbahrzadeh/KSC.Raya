using System.Security.Cryptography;

namespace KSC.Raya.Api.Services;

public interface IKeyService
{
    UserKey GenerateKey(string password);
}

public class KeyService : IKeyService
{
    private byte[] DrivedKey(string password, byte[] salt)
    {
        var pbkdf2 =new Rfc2898DeriveBytes(
            password,
            salt,
            500_000,
            HashAlgorithmName.SHA256);

        return pbkdf2.GetBytes(32);
        
    }

    private UserKey GetUserKey(
        string password,
        byte[] publicKey,
        byte[] privateKey)
    {
        var salt=RandomNumberGenerator.GetBytes(32);
        var key=DrivedKey(password, salt);
        using var aes = Aes.Create();
        aes.GenerateIV();
        aes.Key = key;
        using var encryptor=aes.CreateEncryptor();
        var encryptedPrivateKey = encryptor.TransformFinalBlock(
            privateKey,
            0,
            privateKey.Length);

        return new UserKey(Convert.ToBase64String(publicKey), Convert.ToBase64String(encryptedPrivateKey), Convert.ToBase64String(aes.IV), Convert.ToBase64String(salt));
    }
    public UserKey GenerateKey(string password)
    {
        using var rsa=RSA.Create(4096);

        var publicKey = rsa.ExportSubjectPublicKeyInfo();

        var privateKey = rsa.ExportPkcs8PrivateKey();

        return GetUserKey(password, publicKey, privateKey);
    }
}
public record UserKey(string PublicKey,
                      string EncryptedPrivateKey,
                      string IV,
                      string Salt);