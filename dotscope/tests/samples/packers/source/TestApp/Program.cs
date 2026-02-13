using System;

namespace ConfuserExTestApp
{
    /// <summary>
    /// Test application for ConfuserEx obfuscation testing.
    /// This app contains various patterns that obfuscators typically target:
    /// - String literals
    /// - Method calls between classes
    /// - Simple math operations
    /// - Control flow (if/else, loops, switch)
    /// - Constants
    /// </summary>
    class Program
    {
        private const string AppName = "ConfuserEx Test App";
        private const int MagicNumber = 42;

        static void Main(string[] args)
        {
            Console.WriteLine("=== " + AppName + " ===");
            Console.WriteLine();

            // Test string operations
            var greeter = new Greeter("World");
            greeter.SayHello();
            greeter.SayGoodbye();

            // Test math operations
            var calc = new Calculator();
            Console.WriteLine();
            Console.WriteLine("--- Math Operations ---");
            Console.WriteLine($"Add(10, 5) = {calc.Add(10, 5)}");
            Console.WriteLine($"Subtract(10, 5) = {calc.Subtract(10, 5)}");
            Console.WriteLine($"Multiply(10, 5) = {calc.Multiply(10, 5)}");
            Console.WriteLine($"Divide(10, 5) = {calc.Divide(10, 5)}");
            Console.WriteLine($"Factorial(6) = {calc.Factorial(6)}");
            Console.WriteLine($"Fibonacci(10) = {calc.Fibonacci(10)}");

            // Test control flow
            Console.WriteLine();
            Console.WriteLine("--- Control Flow ---");
            var flow = new ControlFlowDemo();
            flow.DemoIfElse(MagicNumber);
            flow.DemoSwitch(2);
            flow.DemoLoop(5);

            // Test secret strings (typical obfuscation target)
            Console.WriteLine();
            Console.WriteLine("--- Secrets ---");
            var secrets = new SecretHolder();
            Console.WriteLine($"API Key: {secrets.GetApiKey()}");
            Console.WriteLine($"Connection String: {secrets.GetConnectionString()}");
            Console.WriteLine($"Decrypted: {secrets.DecryptSecret("SGVsbG8gV29ybGQ=")}");

            Console.WriteLine();
            Console.WriteLine("=== Done ===");
        }
    }

    class Greeter
    {
        private readonly string _name;
        private const string HelloPrefix = "Hello, ";
        private const string GoodbyePrefix = "Goodbye, ";

        public Greeter(string name)
        {
            _name = name;
        }

        public void SayHello()
        {
            var message = BuildMessage(HelloPrefix, _name);
            Console.WriteLine(message);
        }

        public void SayGoodbye()
        {
            var message = BuildMessage(GoodbyePrefix, _name);
            Console.WriteLine(message);
        }

        private string BuildMessage(string prefix, string name)
        {
            return prefix + name + "!";
        }
    }

    class Calculator
    {
        public int Add(int a, int b)
        {
            return a + b;
        }

        public int Subtract(int a, int b)
        {
            return a - b;
        }

        public int Multiply(int a, int b)
        {
            return a * b;
        }

        public int Divide(int a, int b)
        {
            if (b == 0)
            {
                throw new DivideByZeroException("Cannot divide by zero");
            }
            return a / b;
        }

        public int Factorial(int n)
        {
            if (n <= 1)
                return 1;
            return n * Factorial(n - 1);
        }

        public int Fibonacci(int n)
        {
            if (n <= 0) return 0;
            if (n == 1) return 1;

            int a = 0, b = 1;
            for (int i = 2; i <= n; i++)
            {
                int temp = a + b;
                a = b;
                b = temp;
            }
            return b;
        }
    }

    class ControlFlowDemo
    {
        public void DemoIfElse(int value)
        {
            string result;
            if (value < 0)
            {
                result = "Negative";
            }
            else if (value == 0)
            {
                result = "Zero";
            }
            else if (value < 10)
            {
                result = "Small positive";
            }
            else if (value < 100)
            {
                result = "Medium positive";
            }
            else
            {
                result = "Large positive";
            }
            Console.WriteLine($"Value {value} is: {result}");
        }

        public void DemoSwitch(int choice)
        {
            string action;
            switch (choice)
            {
                case 0:
                    action = "Nothing";
                    break;
                case 1:
                    action = "Start";
                    break;
                case 2:
                    action = "Process";
                    break;
                case 3:
                    action = "Stop";
                    break;
                case 4:
                    action = "Reset";
                    break;
                default:
                    action = "Unknown";
                    break;
            }
            Console.WriteLine($"Choice {choice} means: {action}");
        }

        public void DemoLoop(int iterations)
        {
            int sum = 0;
            for (int i = 1; i <= iterations; i++)
            {
                sum += i;
            }
            Console.WriteLine($"Sum of 1 to {iterations} = {sum}");
        }
    }

    class SecretHolder
    {
        // These strings are typical targets for string encryption
        private const string ApiKeyValue = "sk-12345-ABCDE-67890-FGHIJ";
        private const string ConnectionStringValue = "Server=localhost;Database=TestDb;User=admin;Password=secret123";

        public string GetApiKey()
        {
            return ApiKeyValue;
        }

        public string GetConnectionString()
        {
            return ConnectionStringValue;
        }

        public string DecryptSecret(string base64)
        {
            try
            {
                byte[] data = Convert.FromBase64String(base64);
                return System.Text.Encoding.UTF8.GetString(data);
            }
            catch
            {
                return "Invalid input";
            }
        }

        public string XorEncrypt(string input, byte key)
        {
            char[] output = new char[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                output[i] = (char)(input[i] ^ key);
            }
            return new string(output);
        }
    }
}
