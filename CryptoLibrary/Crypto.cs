using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Text;

namespace CryptoLibrary {
public class Crypto {
        public byte[] ComputeSHA1(byte[] data)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }

        public byte[] ComputeSHA256(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }

        public byte[] ComputeSHA512(byte[] data)
        {
            using (SHA512 sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(data);
            }
        }

        public byte[] DESEncrypt(byte[] data, string key)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key);
                des.IV = Encoding.UTF8.GetBytes(key);
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public byte[] DESDecrypt(byte[] data, string key)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key);
                des.IV = Encoding.UTF8.GetBytes(key);
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = des.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public byte[] AESEncrypt(byte[] data, string key)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = new byte[16]; // Random IV (Initialization Vector)
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public byte[] AESDecrypt(byte[] data, string key)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = new byte[16]; // Random IV (Initialization Vector)
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public byte[] ComputeHMACSHA1(byte[] data, byte[] key)
        {
            using (HMACSHA1 hmacSha1 = new HMACSHA1(key))
            {
                return hmacSha1.ComputeHash(data);
            }
        }

        public byte[] ComputeHMACSHA256(byte[] data, byte[] key)
        {
            using (HMACSHA256 hmacSha256 = new HMACSHA256(key))
            {
                return hmacSha256.ComputeHash(data);
            }
        }

        public byte[] ComputeCRC32(byte[] data)
        {
            using (CRC32 crc32 = new CRC32())
            {
                return crc32.ComputeHash(data);
            }
        }

        public byte[] ComputeMD5(byte[] data)
        {
            using (MD5 md5 = MD5.Create())
            {
                return md5.ComputeHash(data);
            }
        }

        public string ByteArrayToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        class CRC32 : HashAlgorithm
        {
            private const uint Poly = 0xEDB88320;
            private uint[] table;

            public CRC32()
            {
                HashSizeValue = 32;
                InitializeTable();
            }

            public override void Initialize()
            {
                // Do nothing
            }

            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                uint crc = uint.MaxValue;
                for (int i = ibStart; i < ibStart + cbSize; i++)
                {
                    crc = (crc >> 8) ^ table[array[i] ^ crc & 0xFF];
                }
                HashValue = new[] { (byte)(~crc >> 24), (byte)(~crc >> 16), (byte)(~crc >> 8), (byte)(~crc) };
            }

            protected override byte[] HashFinal()
            {
                return (byte[])HashValue.Clone();
            }

            private void InitializeTable()
            {
                table = new uint[256];
                for (uint i = 0; i < 256; i++)
                {
                    uint entry = i;
                    for (int j = 0; j < 8; j++)
                    {
                        if ((entry & 1) == 1)
                            entry = (entry >> 1) ^ Poly;
                        else
                            entry >>= 1;
                    }
                    table[i] = entry;
                }
            }
        }


    }
}
