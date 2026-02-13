using System;
using System.IO;
using System.Reflection;

namespace ResourceTestApp
{
    /// <summary>
    /// Test application for ConfuserEx resource protection testing.
    /// Contains an embedded BMP resource that should survive deobfuscation.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Resource Test App ===");
            Console.WriteLine();

            // Load the embedded resource
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = "ResourceTestApp.testimage.bmp";

            using (var stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    Console.WriteLine("ERROR: Could not find embedded resource!");
                    return;
                }

                Console.WriteLine($"Resource found: {resourceName}");
                Console.WriteLine($"Resource size: {stream.Length} bytes");

                // Read first few bytes to verify it's a valid BMP
                byte[] header = new byte[2];
                stream.Read(header, 0, 2);

                if (header[0] == 0x42 && header[1] == 0x4D) // "BM"
                {
                    Console.WriteLine("Valid BMP header detected!");
                }
                else
                {
                    Console.WriteLine($"WARNING: Unexpected header: {header[0]:X2} {header[1]:X2}");
                }

                // Read the whole resource and compute a simple checksum
                stream.Position = 0;
                byte[] data = new byte[stream.Length];
                stream.Read(data, 0, data.Length);

                int checksum = 0;
                foreach (byte b in data)
                {
                    checksum = (checksum + b) & 0xFFFF;
                }
                Console.WriteLine($"Resource checksum: 0x{checksum:X4}");
            }

            Console.WriteLine();
            Console.WriteLine("=== Done ===");
        }
    }
}
