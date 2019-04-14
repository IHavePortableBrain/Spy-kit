using System.IO;
using System.Security.Cryptography;
using System.Text;
using ConstantsLib;

namespace Cryptography
{
    public static class CryptOps
    {
        public static void Encrypt(string plainFile, string cipherFile, string key)
        {
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] keyBytes = unicode.GetBytes(key);

            FileStream cipherFileStream = new FileStream(cipherFile, FileMode.Create);
            RijndaelManaged rijndaelCryptoSystem = new RijndaelManaged();

            CryptoStream linkStream = new CryptoStream(cipherFileStream,
                rijndaelCryptoSystem.CreateEncryptor(keyBytes, keyBytes),
                CryptoStreamMode.Write);
            FileStream plainFileStream = new FileStream(plainFile, FileMode.Open);

            byte[] plainBuf = new byte[Constants.BUFSIZ];//plainFileStream.Length
            int readBytesCount = -1;
            while (readBytesCount != 0)
            {
                readBytesCount = plainFileStream.Read(plainBuf, 0, plainBuf.Length);
                linkStream.Write(plainBuf, 0, readBytesCount);
            }

            plainFileStream.Close();
            linkStream.Close();
            cipherFileStream.Close();
        }

        public static void Decrypt(string cipherFile, string plainFile, string key)
        {
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] keyBytes = unicode.GetBytes(key);

            FileStream plainFileStream = new FileStream(plainFile, FileMode.Create);
            RijndaelManaged rijndaelCryptoSystem = new RijndaelManaged();
            CryptoStream linkStream = new CryptoStream(plainFileStream,
                rijndaelCryptoSystem.CreateDecryptor(keyBytes, keyBytes),
                CryptoStreamMode.Write);
            FileStream cipherFileStream = new FileStream(cipherFile, FileMode.Open);

            byte[] cipherBuf = new byte[Constants.BUFSIZ];
            int readBytesCount = -1;
            while (readBytesCount != 0)
            {
                readBytesCount = cipherFileStream.Read(cipherBuf, 0, cipherBuf.Length);
                linkStream.Write(cipherBuf, 0, readBytesCount);
            }

            linkStream.Close();
            plainFileStream.Close();
            cipherFileStream.Close();
        }
    }
}