// Writes copies of an input assembly with metadata layouts the CLR's reader accepts but
// ECMA-335 does not describe, or describes only loosely, one variant per file, through
// dnlib (whose writer options ConfuserEx's "invalid metadata" protection is built from).
//
//   MetadataVariants layouts <input.exe> <output-dir>
//   MetadataVariants streams <StreamProbe.exe> <output-dir>
//
// `layouts` covers the `#~` header: the ExtraData word (HeapSizes 0x40), the HasDelete bit
// (0x80) and uncompressed `#-` metadata. Its input is TestApp, so a variant that runs and
// prints what TestApp prints is one the CLR reads as intended.
//
// `streams` covers the stream directory: repeated headers, unknown names and the header
// count. Its input is StreamProbe, which prints one value from each heap. A repeated header
// points at a copy of its heap with that value changed, so the output says which header
// of the name the CLR read; a repeat that would break every lookup if read (`junk_*`) says
// whether the CLR reads it at all.

using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

if (args.Length != 3 || (args[0] != "layouts" && args[0] != "streams"))
{
    Console.Error.WriteLine("usage: MetadataVariants layouts|streams <input.exe> <output-dir>");
    return 2;
}

var (mode, input, outputDir) = (args[0], args[1], args[2]);
Directory.CreateDirectory(outputDir);
var inputBytes = File.ReadAllBytes(input);

var variants = mode == "layouts" ? Layouts() : Streams();
foreach (var (name, configure) in variants)
{
    using var module = ModuleDefMD.Load(inputBytes);
    var options = new ModuleWriterOptions(module);
    // Keep every row, token and heap offset where the input has them, so a variant differs
    // from the input only in the layout under test, and a heap copied from the input is
    // valid in the output.
    options.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
    configure(options);
    var path = Path.Combine(outputDir, name + ".exe");
    module.Write(path, options);
    Console.WriteLine(path);
}

return 0;

IEnumerable<(string, Action<ModuleWriterOptions>)> Layouts()
{
    yield return ("extradata", o => o.MetadataOptions.TablesHeapOptions.ExtraData = 0x12345678);
    // dnlib writes `#-` whenever HasDelete is set: the bit means nothing in `#~`.
    yield return ("hasdelete", o => o.MetadataOptions.TablesHeapOptions.HasDeletedRows = true);
    yield return ("enc", Enc);
    yield return ("enc_extradata", o =>
    {
        Enc(o);
        o.MetadataOptions.TablesHeapOptions.ExtraData = 0x12345678;
    });
}

IEnumerable<(string, Action<ModuleWriterOptions>)> Streams()
{
    yield return ("probe", _ => { });
    foreach (var enc in new[] { false, true })
    {
        var suffix = enc ? "_enc" : "";
        Action<ModuleWriterOptions> format = enc ? Enc : _ => { };
        foreach (var (heap, changed) in ChangedHeaps())
        {
            yield return ($"{heap}_after{suffix}", o => { format(o); After(o, changed); });
            yield return ($"{heap}_before{suffix}", o => { format(o); Before(o, changed); });
        }
        // Repeats of every heap that break every lookup if read: ConfuserEx's layout.
        yield return ($"junk_after{suffix}", o => { format(o); After(o, Junk()); });
        yield return ($"junk_before{suffix}", o => { format(o); Before(o, Junk()); });
    }
    // Names the CLR gives a meaning to although ECMA-335 does not list them: `#Schema`,
    // which ConfuserEx appends, `#Pdb` and `#JTD` (which makes every table column four
    // bytes wide). Each alone, and `#Schema` with a changed repeat of `#US` on either side,
    // to see whether it changes which header of a name is read.
    var us = ChangedHeaps().Single(h => h.Item1 == "us").Item2;
    foreach (var name in new[] { "Schema", "Pdb", "JTD" })
    {
        yield return ($"{name.ToLowerInvariant()}_after", o => After(o, Raw($"#{name}", 0, 0, 0, 0)));
        yield return ($"{name.ToLowerInvariant()}_before", o => Before(o, Raw($"#{name}", 0, 0, 0, 0)));
    }
    yield return ("us_after_schema_after", o => After(o, us, Raw("#Schema", 0, 0, 0, 0)));
    yield return ("schema_after_us_after", o => After(o, Raw("#Schema", 0, 0, 0, 0), us));
    yield return ("us_before_schema_after", o => { Before(o, us); After(o, Raw("#Schema", 0, 0, 0, 0)); });
    yield return ("junk_after_schema_after", o => After(o, [.. Junk(), Raw("#Schema", 0, 0, 0, 0)]));
    // Names the CLR does not use.
    foreach (var count in new[] { 1, 2, 3, 4, 5, 6, 7, 8 })
    {
        yield return ($"unknown_after_{count}", o => After(o, Unknown(count)));
    }
    yield return ("unknown_before_1", o => Before(o, Unknown(1)));
    yield return ("unknown_name_hash", o => After(o, Raw("#", 0, 0, 0, 0)));
    yield return ("unknown_name_tilde_prefix", o => After(o, Raw("#~~", 0, 0, 0, 0)));
}

static void Enc(ModuleWriterOptions o) => o.MetadataOptions.TablesHeapOptions.UseENC = true;

// Heaps placed before or after the real ones in the stream directory.
static void Before(ModuleWriterOptions o, params IHeap[] heaps) =>
    o.MetadataOptions.MetadataHeapsAdded += (_, e) => e.Heaps.InsertRange(0, heaps);

static void After(ModuleWriterOptions o, params IHeap[] heaps) =>
    o.MetadataOptions.MetadataHeapsAdded += (_, e) => e.Heaps.AddRange(heaps);

// A heap whose bytes are given verbatim.
static RawHeap Raw(string name, params byte[] data) => new(name, data);

static IHeap[] Junk() =>
[
    Raw("#Strings", 0, 0, 0, 0),
    Raw("#US", 0, 0, 0, 0),
    Raw("#Blob", 0, 0, 0, 0),
    Raw("#GUID", new byte[16]),
];

static IHeap[] Unknown(int count) =>
    Enumerable.Range(1, count).Select(i => (IHeap)Raw($"#Unknown{i}", 0, 0, 0, 0)).ToArray();

// Each StreamProbe heap with the value the probe prints from it changed: the case of the
// marker text swapped, and the MVID's bytes inverted. Offsets and lengths are unchanged.
IEnumerable<(string, IHeap)> ChangedHeaps()
{
    using var module = ModuleDefMD.Load(inputBytes);
    var md = module.Metadata;
    yield return ("strings", Raw("#Strings", SwapCase(Bytes(md.StringsStream), Encoding.ASCII.GetBytes("StringsMarker"))));
    yield return ("us", Raw("#US", SwapCase(Bytes(md.USStream), Encoding.Unicode.GetBytes("UserStringMarker"))));
    yield return ("blob", Raw("#Blob", SwapCase(Bytes(md.BlobStream), Encoding.ASCII.GetBytes("BlobMarker"))));
    yield return ("guid", Raw("#GUID", Bytes(md.GuidStream).Select(b => (byte)~b).ToArray()));
}

static byte[] Bytes(dnlib.DotNet.MD.DotNetStream stream)
{
    var reader = stream.CreateReader();
    return reader.ReadBytes((int)reader.Length);
}

// Swaps the case of the ASCII letters of the one occurrence of `marker` in `heap`.
static byte[] SwapCase(byte[] heap, byte[] marker)
{
    var at = heap.AsSpan().IndexOf(marker);
    if (at < 0 || heap.AsSpan(at + 1).IndexOf(marker) >= 0)
    {
        throw new InvalidOperationException("the marker must occur exactly once in its heap");
    }
    for (var i = at; i < at + marker.Length; i++)
    {
        if (char.IsAsciiLetter((char)heap[i]))
        {
            heap[i] ^= 0x20;
        }
    }
    return heap;
}

sealed class RawHeap(string name, byte[] data) : HeapBase
{
    public override string Name => name;

    public override uint GetRawLength() => (uint)data.Length;

    protected override void WriteToImpl(DataWriter writer) => writer.WriteBytes(data);
}
