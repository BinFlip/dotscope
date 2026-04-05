using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;

namespace ConfuserExTestApp
{
    /// <summary>
    /// Test application for obfuscation testing.
    /// This app contains various patterns that obfuscators typically target:
    /// - String literals
    /// - Method calls between classes
    /// - Simple math operations
    /// - Control flow (if/else, loops, switch)
    /// - Constants
    /// - Char literals (JIEJIE.NET char encryption)
    /// - Static array initializers (JIEJIE.NET array init encryption)
    /// - lock() statements (JIEJIE.NET lock structure obfuscation)
    /// - using/IDisposable (JIEJIE.NET using structure obfuscation)
    /// - Enum method arguments (JIEJIE.NET enum parameter encryption)
    /// - typeof() expressions (JIEJIE.NET typeof encryption)
    /// </summary>
    class Program
    {
        private const string AppName = "Test App";
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

            // Test char/enum/typeof/array/lock/using patterns
            Console.WriteLine();
            Console.WriteLine("--- Extended Patterns ---");
            var patterns = new ExtendedPatterns();
            patterns.DemoCharOperations();
            patterns.DemoEnumArguments();
            patterns.DemoTypeOf();
            patterns.DemoStaticArrayInit();
            patterns.DemoLockAndUsing();
            patterns.DemoEmbeddedResources();

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

    enum Priority
    {
        Low = 0,
        Normal = 1,
        High = 2,
        Critical = 3
    }

    enum Color
    {
        Red = 0,
        Green = 1,
        Blue = 2,
        Yellow = 3,
        White = 4
    }

    class ExtendedPatterns
    {
        // Static array initializer — target for JIEJIE.NET array init encryption
        // (RuntimeHelpers.InitializeArray from RVA data)
        private static readonly int[] LookupTable = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
        private static readonly byte[] XorKey = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

        private readonly object _syncLock = new object();
        private int _counter;

        /// <summary>
        /// Char literals — target for JIEJIE.NET char value encryption.
        /// Each char constant becomes an Int32ValueContainer field load.
        /// </summary>
        public void DemoCharOperations()
        {
            char separator = '-';
            char open = '[';
            char close = ']';
            char space = ' ';
            char newline = '\n';

            string input = "Hello, World!";
            int vowelCount = 0;
            int consonantCount = 0;
            foreach (char c in input)
            {
                char lower = char.ToLower(c);
                if (lower == 'a' || lower == 'e' || lower == 'i' || lower == 'o' || lower == 'u')
                    vowelCount++;
                else if (lower >= 'a' && lower <= 'z')
                    consonantCount++;
            }

            Console.Write(open);
            Console.Write("Chars" + separator + space);
            Console.Write($"vowels={vowelCount}" + separator + space);
            Console.Write($"consonants={consonantCount}");
            Console.Write(close);
            Console.Write(newline);

            // Additional char comparisons to give JIEJIE.NET more targets
            char tab = '\t';
            char quote = '"';
            char backslash = '\\';
            Console.WriteLine($"Special chars: tab={tab == '\t'} quote={quote == '\"'} backslash={backslash == '\\'}");
        }

        /// <summary>
        /// Enum values as method arguments — target for JIEJIE.NET enum parameter encryption.
        /// Each enum literal becomes an Int32ValueContainer field load.
        /// </summary>
        public void DemoEnumArguments()
        {
            ProcessTask("Task A", Priority.High);
            ProcessTask("Task B", Priority.Low);
            ProcessTask("Task C", Priority.Critical);
            ProcessTask("Task D", Priority.Normal);

            string colorName = GetColorName(Color.Blue);
            Console.WriteLine($"Color: {colorName}");
            colorName = GetColorName(Color.Yellow);
            Console.WriteLine($"Color: {colorName}");

            SetMode(ConsoleColor.Green);
            SetMode(ConsoleColor.Red);
        }

        private void ProcessTask(string name, Priority priority)
        {
            string urgency;
            switch (priority)
            {
                case Priority.Low:
                    urgency = "low";
                    break;
                case Priority.Normal:
                    urgency = "normal";
                    break;
                case Priority.High:
                    urgency = "high";
                    break;
                case Priority.Critical:
                    urgency = "CRITICAL";
                    break;
                default:
                    urgency = "unknown";
                    break;
            }
            Console.WriteLine($"Task '{name}' priority: {urgency}");
        }

        private string GetColorName(Color color)
        {
            switch (color)
            {
                case Color.Red: return "Red";
                case Color.Green: return "Green";
                case Color.Blue: return "Blue";
                case Color.Yellow: return "Yellow";
                case Color.White: return "White";
                default: return "Unknown";
            }
        }

        private void SetMode(ConsoleColor color)
        {
            Console.WriteLine($"Mode set to {color}");
        }

        /// <summary>
        /// typeof() expressions — target for JIEJIE.NET typeof encryption.
        /// Each typeof becomes a RuntimeTypeHandleContainer lookup.
        /// </summary>
        public void DemoTypeOf()
        {
            Type intType = typeof(int);
            Type stringType = typeof(string);
            Type objectType = typeof(object);
            Type boolType = typeof(bool);
            Type arrayType = typeof(int[]);
            Type listType = typeof(System.Collections.Generic.List<>);

            Console.WriteLine($"typeof(int) = {intType.FullName}");
            Console.WriteLine($"typeof(string) = {stringType.FullName}");
            Console.WriteLine($"typeof(object) = {objectType.FullName}");
            Console.WriteLine($"typeof(bool) = {boolType.FullName}");

            // Type comparisons
            object value = 42;
            bool isInt = value.GetType() == typeof(int);
            bool isString = value.GetType() == typeof(string);
            Console.WriteLine($"42 is int: {isInt}, is string: {isString}");

            // Type checking
            Console.WriteLine($"int[] is array: {arrayType.IsArray}");
            Console.WriteLine($"List<> is generic: {listType.IsGenericTypeDefinition}");
        }

        /// <summary>
        /// Static array initializers — target for JIEJIE.NET array init encryption.
        /// Arrays initialized from RVA data use RuntimeHelpers.InitializeArray.
        /// </summary>
        public void DemoStaticArrayInit()
        {
            // Use the static arrays
            int sum = 0;
            for (int i = 0; i < LookupTable.Length; i++)
            {
                sum += LookupTable[i];
            }
            Console.WriteLine($"Prime sum: {sum}");

            // XOR operation using static key
            byte[] data = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0x21, 0x21 };
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= XorKey[i % XorKey.Length];
            }
            Console.WriteLine($"XOR result: {BitConverter.ToString(data)}");
        }

        /// <summary>
        /// lock() and using statements — targets for JIEJIE.NET lock/using structure obfuscation.
        /// lock() calls become JIEJIEHelper.Monitor_Enter redirections.
        /// using calls become JIEJIEHelper.MyDispose redirections.
        /// </summary>
        public void DemoLockAndUsing()
        {
            // lock() statement — target for Monitor_Enter/Monitor_Exit redirection
            lock (_syncLock)
            {
                _counter++;
                Console.WriteLine($"Counter (locked): {_counter}");
            }

            lock (_syncLock)
            {
                _counter += 10;
                Console.WriteLine($"Counter (locked): {_counter}");
            }

            // using statement — target for IDisposable.Dispose redirection
            using (var writer = new StringWriter())
            {
                writer.Write("Hello from ");
                writer.Write("using block");
                Console.WriteLine($"StringWriter: {writer}");
            }

            // Nested using
            using (var outer = new StringWriter())
            {
                outer.Write("Outer");
                using (var inner = new StringWriter())
                {
                    inner.Write("Inner");
                    Console.WriteLine($"Nested using: {outer} + {inner}");
                }
            }

            // Multiple lock operations to provide more targets
            int result;
            lock (_syncLock)
            {
                result = _counter * 2;
            }
            Console.WriteLine($"Result: {result}");
        }

        /// <summary>
        /// Embedded resource access — target for JIEJIE.NET resource encryption.
        /// GetManifestResourceStream calls are redirected through SMF_* helpers.
        /// </summary>
        public void DemoEmbeddedResources()
        {
            var assembly = Assembly.GetExecutingAssembly();

            // Read text resource
            using (var stream = assembly.GetManifestResourceStream("ConfuserExTestApp.Resources.greeting.txt"))
            {
                if (stream != null)
                {
                    using (var reader = new StreamReader(stream))
                    {
                        string firstLine = reader.ReadLine();
                        Console.WriteLine($"Resource text: {firstLine}");
                    }
                }
                else
                {
                    Console.WriteLine("Resource text: not found");
                }
            }

            // Read binary resource
            using (var stream = assembly.GetManifestResourceStream("ConfuserExTestApp.Resources.data.bin"))
            {
                if (stream != null)
                {
                    byte[] buffer = new byte[8];
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);
                    Console.WriteLine($"Resource binary: {bytesRead} bytes, starts with '{System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead)}'");
                }
                else
                {
                    Console.WriteLine("Resource binary: not found");
                }
            }

            // List all resource names
            string[] names = assembly.GetManifestResourceNames();
            Console.WriteLine($"Resource count: {names.Length}");
            foreach (string name in names)
            {
                Console.WriteLine($"  Resource: {name}");
            }
        }
    }
}
