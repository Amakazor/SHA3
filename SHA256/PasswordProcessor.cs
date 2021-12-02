using System;

namespace Amakazor.Security.Hashing.SHA3
{
    public static class PasswordProcessor
    {
        public static string HashAndSaltPassword(string password, Func<string, PreviewData, string> hashingFunction)
        {
            password = password.Trim();

            string salt = Guid.NewGuid().ToString();
            password = salt + password;
            string hash = hashingFunction(password, new PreviewData(false, false, false));
            hash = hash.Replace(" ", "");
            return salt + "+" + hash;
        }

        public static bool VerifyPassword(string hash, string password, Func<string, PreviewData, string> hashingFunction)
        {
            hash = hash.Trim();
            password = password.Trim();

            string[] splitHash = hash.Split('+');

            if (splitHash.Length == 2)
            {
                string salt = splitHash[0];

                password = salt + password;
                string newHash = hashingFunction(password, new PreviewData(false, false, false));
                newHash = newHash.Replace(" ", "");
                newHash = salt + "+" + newHash;
                return hash.Equals(newHash);
            }
            return false;
        }
    }
}
