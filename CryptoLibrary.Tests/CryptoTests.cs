using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CryptoLibrary.Tests
{
    public class CryptoTests
    {
        private readonly Crypto crypto;

        public CryptoTests()
        {
            crypto = new Crypto();
        }

        [Fact]
        public void ComputeSHA1_ValidData_ComputesCorrectHash()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!"); //hex : 48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21

            // Act
            byte[] hash = crypto.ComputeSHA1(data);

            // Assert
            string expectedHash = "0A 0A 9F 2A 67 72 94 25 57 AB 53 55 D7 6A F4 42 F8 F6 5E 01";
            expectedHash = expectedHash.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHash, ByteArrayToHex(hash));
        }

        [Fact]
        public void ComputeSHA256_ValidData_ComputesCorrectHash()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!"); //hex : 48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21

            // Act
            byte[] hash = crypto.ComputeSHA256(data);

            // Assert
            string expectedHash = "DF FD 60 21 BB 2B D5 B0 AF 67 62 90 80 9E C3 A5 31 91 DD 81 C7 F7 0A 4B 28 68 8A 36 21 82 98 6F";
            expectedHash = expectedHash.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHash, ByteArrayToHex(hash));
        }

        [Fact]
        public void ComputeSHA512_ValidData_ComputesCorrectHash()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!"); //hex : 48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21

            // Act
            byte[] hash = crypto.ComputeSHA512(data);

            // Assert
            string expectedHash = "37 4D 79 4A 95 CD CF D8 B3 59 93 18 5F EF 9B A3 68 F1 60 D8 DA F4 32 D0 8B A9 F1 ED 1E 5A BE 6C C6 92 91 E0 FA 2F E0 00 6A 52 57 0E F1 8C 19 DE F4 E6 17 C3 3C E5 2E F0 A6 E5 FB E3 18 CB 03 87";
            expectedHash = expectedHash.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHash, ByteArrayToHex(hash));
        }

        [Fact]
        public void DESEncryptAndDecrypt_ValidData_EncryptsAndDecryptsCorrectly()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!"); //hex : 48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21
            string key = "12345678"; //  hex : 31 32 33 34 35 36 37 38

            // Act
            byte[] encrypted = crypto.DESEncrypt(data, key);
            byte[] decrypted = crypto.DESDecrypt(encrypted, key);

            // Assert
            string decryptedText = Encoding.UTF8.GetString(decrypted);
            Assert.Equal("Hello, World!", decryptedText);
        }

        [Fact]
        public void AESEncryptAndDecrypt_ValidData_EncryptsAndDecryptsCorrectly()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!"); //hex : 48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21
            string key = "1234567891234567"; //  hex : 31 32 33 34 35 36 37 38 39 31 32 33 34 35 36 37

            // Act
            byte[] encrypted = crypto.AESEncrypt(data, key);
            byte[] decrypted = crypto.AESDecrypt(encrypted, key);

            // Assert
            string decryptedText = Encoding.UTF8.GetString(decrypted);
            Assert.Equal("Hello, World!", decryptedText);
        }

        [Fact]
        public void ComputeHMACSHA1_ValidData_ComputesCorrectHMAC()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!"); //hex : 48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21
            byte[] key = Encoding.UTF8.GetBytes("SampleKey123"); //  hex : 53 61 6D 70 6C 65 4B 65 79 31 32 33

            // Act
            byte[] hmac = crypto.ComputeHMACSHA1(data, key);

            // Assert
            string expectedHmac = "87 A2 F4 E0 B4 A6 2D 05 9F A7 F8 47 77 F4 04 9A 87 21 D4 B8";
            expectedHmac = expectedHmac.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHmac, ByteArrayToHex(hmac));
        }

        [Fact]
        public void ComputeHMACSHA256_ValidData_ComputesCorrectHMAC()
        {
            // Arrange
            byte[] data = Encoding.UTF8.GetBytes("Hello, World!"); //hex : 48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21
            byte[] key = Encoding.UTF8.GetBytes("SampleKey123"); //  hex : 53 61 6D 70 6C 65 4B 65 79 31 32 33

            // Act
            byte[] hmac = crypto.ComputeHMACSHA256(data, key);

            // Assert
            string expectedHmac = "9E 73 D9 BA 45 E5 7D 8F 25 FC 1F 46 EA 6F A4 A9 AE 6F 7D 85 B4 58 60 D3 31 BF 6E E9 6F 5D 3A 49";
            expectedHmac = expectedHmac.Trim().Replace(" ", "").ToLower();
            Assert.Equal(expectedHmac, ByteArrayToHex(hmac));
        }

        // Add more unit tests for other methods

        private string ByteArrayToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
