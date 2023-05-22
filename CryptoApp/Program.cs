using System.Text;

internal class Program {
  private static void Main(string[] args) {
    Console.WriteLine("Crypto Application Running..");
    var cryptoLibrary = new CryptoLibrary.Crypto();
        string message = "Hello, world!";
        byte[] data = Encoding.UTF8.GetBytes(message);

        // SHA-1
        byte[] sha1Hash = cryptoLibrary.ComputeSHA1(data);
        Console.WriteLine("SHA-1: " +  cryptoLibrary.ByteArrayToHex(sha1Hash));

        // SHA-256
        byte[] sha256Hash = cryptoLibrary.ComputeSHA256(data);
        Console.WriteLine("SHA-256: " + cryptoLibrary.ByteArrayToHex(sha256Hash));

        // SHA-512
        byte[] sha512Hash = cryptoLibrary.ComputeSHA512(data);
        Console.WriteLine("SHA-512: " + cryptoLibrary.ByteArrayToHex(sha512Hash));

        // DES
        string desKey = "mykey123"; // 8 characters for DES
        byte[] desEncryptedData = cryptoLibrary.DESEncrypt(data, desKey);
        byte[] desDecryptedData = cryptoLibrary.DESDecrypt(desEncryptedData, desKey);
        Console.WriteLine("DES Decrypted: " + Encoding.UTF8.GetString(desDecryptedData));

        // AES
        string aesKey = "myaeskey12345678"; // 16 characters for AES-128, 24 characters for AES-192, 32 characters for AES-256
        byte[] aesEncryptedData = cryptoLibrary.AESEncrypt(data, aesKey);
        byte[] aesDecryptedData = cryptoLibrary.AESDecrypt(aesEncryptedData, aesKey);
        Console.WriteLine("AES Decrypted: " + Encoding.UTF8.GetString(aesDecryptedData));

        // HMAC-SHA1
        byte[] hmacSha1Key = Encoding.UTF8.GetBytes("myhmackey");
        byte[] hmacSha1Hash = cryptoLibrary.ComputeHMACSHA1(data, hmacSha1Key);
        Console.WriteLine("HMAC-SHA1: " + cryptoLibrary.ByteArrayToHex(hmacSha1Hash));

        // HMAC-SHA256
        byte[] hmacSha256Key = Encoding.UTF8.GetBytes("myhmac256key");
        byte[] hmacSha256Hash = cryptoLibrary.ComputeHMACSHA256(data, hmacSha256Key);
        Console.WriteLine("HMAC-SHA256: " + cryptoLibrary.ByteArrayToHex(hmacSha256Hash));

        // CRC32
        byte[] crc32Hash = cryptoLibrary.ComputeCRC32(data);
        Console.WriteLine("CRC32: " + cryptoLibrary.ByteArrayToHex(crc32Hash));

        // MD5
        byte[] md5Hash = cryptoLibrary.ComputeMD5(data);
        Console.WriteLine("MD5: " + cryptoLibrary.ByteArrayToHex(md5Hash));

        Console.ReadLine();
    }
}
