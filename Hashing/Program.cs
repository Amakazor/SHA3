using System;
using System.IO;

namespace Amakazor.Security.Hashing.SHA3
{
    public static class Program
    {
        public static void Main()
        {
            while (true)
            {
                Console.WriteLine("What do you want to do?");
                Console.WriteLine();
                Console.WriteLine("1. Preview");
                Console.WriteLine("2. Hash password");
                Console.WriteLine("3. Check validity of hashed password");
                Console.WriteLine("4. Hash file");
                Console.WriteLine("5. Check validity of hashed file");
                Console.WriteLine("6. Exit");
                Console.WriteLine();

                int selected;
                bool firstTime = true;

                while (true)
                {
                    if (!firstTime)
                    {
                        Console.WriteLine("Please select valid option: ");
                        Console.WriteLine();
                    }

                    string input = Console.ReadLine();
                    if (int.TryParse(input, out selected) && (selected == 1 || selected == 2 || selected == 3 || selected == 4 || selected == 5 || selected == 6))
                    {
                        break;
                    }
                    firstTime = false;
                }

                bool breakAll = false;

                switch (selected)
                {
                    case 1:
                        Preview();
                        break;
                    case 2:
                        HashPassword();
                        break;
                    case 3:
                        VerifyPassword();
                        break;
                    case 4:
                        HashFile();
                        break;
                    case 5:
                        ValidateFileHash();
                        break;
                    case 6:
                        breakAll = true;
                        break;
                }

                if (breakAll) break;
            }
        }

        private static void Preview()
        {
            Func<string, PreviewData, string> hashFunction = GetHashFunction();

            Console.WriteLine("Select an option:");
            Console.WriteLine();
            Console.WriteLine("1. Pause on every action");
            Console.WriteLine("2. Do not pause");
            Console.WriteLine();

            int selectedPause;
            bool firstTime = true;

            while (true)
            {
                if (!firstTime)
                {
                    Console.WriteLine("Please select valid option: ");
                    Console.WriteLine();
                }

                string input1 = Console.ReadLine();
                if (int.TryParse(input1, out selectedPause) && (selectedPause == 1 || selectedPause == 2))
                {
                    break;
                }
                firstTime = false;
            }

            bool pause = selectedPause switch
            {
                1 => true,
                2 => false,
                _ => throw new NotImplementedException(),
            };

            Console.WriteLine("Select an option:");
            Console.WriteLine();
            Console.WriteLine("1. High level of detail");
            Console.WriteLine("2. Low level of detail");
            Console.WriteLine();

            int selectedDetail;
            firstTime = true;

            while (true)
            {
                if (!firstTime)
                {
                    Console.WriteLine("Please select valid option: ");
                    Console.WriteLine();
                }

                string input2 = Console.ReadLine();
                if (int.TryParse(input2, out selectedDetail) && (selectedDetail == 1 || selectedDetail == 2))
                {
                    break;
                }
                firstTime = false;
            }

            bool detail = selectedDetail switch
            {
                1 => true,
                2 => false,
                _ => throw new NotImplementedException(),
            };

            PreviewData previewData = new(true, pause, detail);

            Console.WriteLine("Enter text to hash:");
            Console.WriteLine();

            string input = Console.ReadLine();

            hashFunction(input, previewData);
        }

        private static void HashPassword()
        {
            Func<string, PreviewData, string> hashFunction = GetHashFunction();

            Console.WriteLine("Enter text to hash:");
            Console.WriteLine();

            string password = Console.ReadLine();

            Console.WriteLine(PasswordProcessor.HashAndSaltPassword(password, hashFunction));
        }
        
        private static void VerifyPassword()
        {
            Func<string, PreviewData, string> hashFunction = GetHashFunction();

            Console.WriteLine("Enter password to verify:");
            Console.WriteLine();

            string password = Console.ReadLine();
            
            Console.WriteLine("Enter hash to verify password with:");
            Console.WriteLine();

            string hash = Console.ReadLine();

            Console.WriteLine(PasswordProcessor.VerifyPassword(hash, password, hashFunction) ? "Hash is valid" : "Hash is invalid");
        }

        private static void HashFile()
        {
            Func<string, PreviewData, string> hashFunction = GetHashFunction();

            Console.WriteLine("Enter full path to a file to hash:");
            Console.WriteLine();

            string path = Console.ReadLine();

            if (File.Exists(path))
            {
                Console.WriteLine();
                Console.WriteLine(hashFunction(System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(path)), new PreviewData(false, false, false)).Replace(" ", ""));
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("File is missing");
            }

        }

        private static void ValidateFileHash()
        {
            Func<string, PreviewData, string> hashFunction = GetHashFunction();

            Console.WriteLine("Enter hash to verify file with:");
            Console.WriteLine();

            string hash = Console.ReadLine();

            Console.WriteLine("Enter full path to a file to hash:");
            Console.WriteLine();

            string path = Console.ReadLine();

            if (File.Exists(path))
            {
                string newHash = hashFunction(System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(path)), new PreviewData(false, false, false)).Replace(" ", "");
                Console.WriteLine();
                Console.WriteLine(hash == newHash ? "Hash is valid" : "Hash is invalid");
                Console.WriteLine();

            }
            else
            {
                Console.WriteLine("File is missing");
            }

        }

        private static Func<string, PreviewData, string> GetHashFunction()
        {
            Console.WriteLine("Select hashing function:");
            Console.WriteLine();
            Console.WriteLine("1. SHA3-224");
            Console.WriteLine("2. SHA3-256");
            Console.WriteLine("3. SHA3-384");
            Console.WriteLine("4. SHA3-512");
            Console.WriteLine();

            int selectedFunction;
            bool firstTime = true;

            while (true)
            {
                if (!firstTime)
                {
                    Console.WriteLine("Please select valid function: ");
                    Console.WriteLine();
                }

                string input = Console.ReadLine();
                if (int.TryParse(input, out selectedFunction) && (selectedFunction == 1 || selectedFunction == 2 || selectedFunction == 3 || selectedFunction == 4))
                {
                    break;
                }
                firstTime = false;
            }

            return selectedFunction switch
            {
                1 => SHA3.SHA224,
                2 => SHA3.SHA256,
                3 => SHA3.SHA384,
                4 => SHA3.SHA512,
                _ => throw new NotImplementedException(),
            };
        }
    }
}