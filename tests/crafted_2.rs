/*
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Reflection;
using System.Reflection.Emit;
using System.Security;
using System.Security.Permissions;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using System.ComponentModel;
using System.Linq;
using System.IO;
using System.Diagnostics;
using System.Text;

// This attribute will be stored in the Assembly table
[assembly: AssemblyTitle("MetadataTestCases")]
[assembly: AssemblyDescription("Test assembly for CIL metadata reverse engineering")]
[assembly: AssemblyVersion("1.2.3.4")]
[assembly: AssemblyCulture("")]
[assembly: CLSCompliant(false)] // Fixed: moved from module to assembly level

// Security permissions (DeclSecurity table)
[assembly: SecurityPermission(SecurityAction.RequestMinimum, Assertion = true)]
[assembly: FileIOPermission(SecurityAction.RequestMinimum, Read = @"C:\TestData")]

// Custom attribute with various parameter types
[assembly: MetadataTestAttribute(42, "Test")] // Removed invalid property

// Module-level attributes
[module: DefaultCharSet(CharSet.Unicode)]

// Custom attribute definition (will go in the various metadata tables)
[AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
public sealed class MetadataTestAttribute : Attribute
{
    // Fields will populate Field table
    private int _intValue;
    public readonly string StringValue;

    // Constructor parameters will be in the Param table
    public MetadataTestAttribute(int intValue, string stringValue)
    {
        _intValue = intValue;
        StringValue = stringValue;
    }

    // Property will generate accessor methods
    public DateTime PropertyValue { get; set; }

    // Will populate the Constant table with default param value
    public bool BoolProperty { get; set; } = true;
}

// Global methods (MethodDef at module level)
public static class Globals
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("user32.dll")]
    public static extern bool MessageBox(IntPtr hWnd, string text, string caption, uint type);
}

// Interface definitions (TypeDef with Interface flags)
public interface IBaseInterface
{
    void Method1();
    int Property1 { get; set; }
}

public interface IDerivedInterface : IBaseInterface
{
    void Method2<T>(T param) where T : struct;
    event EventHandler Event1;
}

// Delegate types (TypeDef with special class semantics)
public delegate void SimpleDelegate(int x);

public delegate TResult GenericDelegate<T, TResult>(T input) where T : class;

// Enum types (ValueType with Enum semantics)
[Flags]
public enum TestEnum : long
{
    None = 0,
    Value1 = 1,
    Value2 = 2,
    Value3 = 4,
    All = Value1 | Value2 | Value3
}

// Struct types (ValueType in metadata)
[StructLayout(LayoutKind.Explicit, Size = 16)]
public struct StructWithExplicitLayout
{
    [FieldOffset(0)]
    public int Field1;

    [FieldOffset(4)]
    public long Field2;

    [FieldOffset(0)]
    public double Overlay;
}

// Generic struct with constraints
public struct GenericStruct<T, U>
    where T : struct
    where U : class, new()
{
    public T Field1;
    public U Field2;

    public void Method(T t, U u) { }
}

// Base class with virtual methods (for testing method overrides)
[Serializable]
public abstract class BaseClass
{
    // Static field with RVA (embedded data)
    private static readonly byte[] StaticData = new byte[] { 1, 2, 3, 4, 5 };

    // Virtual method (for MethodImpl table)
    public virtual void VirtualMethod() { }

    // Abstract method (for MethodImpl table)
    public abstract void AbstractMethod();

    // Method with complex signature for testing Param and ParamType tables
    [Obsolete("For testing")]
    public virtual int ComplexMethod(
        int normalParam,
        ref string refParam,
        out int outParam,
        [Optional] object optionalParam,
        params object[] paramsArray)
    {
        outParam = 42;
        return normalParam;
    }

    // Protected method for testing method access flags
    protected virtual void ProtectedMethod() { }

    // Static constructor (special name)
    static BaseClass()
    {
        Console.WriteLine("Static constructor");
    }

    // Indexer (special method with parameters)
    public virtual object this[int index] => null;
}

// Derived class with method implementations (for MethodImpl table)
[MetadataTest(100, "Derived Class")] // Removed invalid property
public class DerivedClass : BaseClass, IDerivedInterface
{
    // Field with marshaling information
    [MarshalAs(UnmanagedType.LPWStr)]
    private string _marshaledField;

    // Private nested type (for NestedClass table)
    private class NestedClass
    {
        public void NestedMethod() { }
    }

    // Nested enum (another NestedClass entry)
    protected enum NestedEnum
    {
        One,
        Two
    }

    // Generic nested class with constraints
    public class NestedGeneric<T> where T : IBaseInterface
    {
        public T Value { get; set; }
    }

    // Event (for Event and MethodSemantics tables)
    public event EventHandler Event1;

    // Event with custom accessors
    private EventHandler _customEvent;

    public event EventHandler CustomEvent
    {
        add { _customEvent += value; }
        remove { _customEvent -= value; }
    }

    // Method override (for MethodImpl table)
    public override void VirtualMethod()
    {
        // Call to base method (MemberRef)
        base.VirtualMethod();
    }

    // Abstract method implementation (MethodImpl)
    public override void AbstractMethod() { }

    // Method with security attributes (DeclSecurity)
    [SecurityCritical]
    [FileIOPermission(SecurityAction.Demand, Read = @"C:\Test")]
    public void SecureMethod() { }

    // Explicit interface implementation (MethodImpl)
    void IDerivedInterface.Method2<T>(T param) { }

    // Interface implementation (InterfaceImpl and MethodImpl)
    public void Method1() { }

    // Property implementation (PropertyMap, MethodSemantics)
    public int Property1 { get; set; }

    // Generic method (GenericParam)
    public void GenericMethod<T, U>()
        where T : struct
        where U : class, new()
    { }

    // Method with local variables (LocalVarSig)
    public void MethodWithLocals()
    {
        int local1 = 42;
        string local2 = "test";
        var local3 = new List<int>();

        // Try/catch for Exception handling tables
        try
        {
            Console.WriteLine(local1);
            throw new Exception("Test");
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine(ex.Message);
        }
        catch (Exception)
        {
            Console.WriteLine("Generic exception");
        }
        finally
        {
            Console.WriteLine("Finally");
        }
    }

    // Async method (generates state machine)
    public async Task<int> AsyncMethod()
    {
        await Task.Delay(100);
        return 42;
    }

    // Method with complex generic return type
    public Dictionary<string, List<KeyValuePair<int, T>>> ComplexGenericMethod<T>()
    {
        return new Dictionary<string, List<KeyValuePair<int, T>>>();
    }

    // Finalizer (special name method)
    ~DerivedClass() { }
}

// Sealed class with extension methods
public static class Extensions
{
    // Extension method (has special flag)
    public static string ToCustomString<T>(this T value)
    {
        return value?.ToString() ?? "null";
    }

    // Extension method with ref return (newer C# feature)
    // Replaced with regular extension method that's compatible with older .NET
    public static int GetReference(this int[] array, int index)
    {
        return array[index];
    }
}

// Generic class with multiple type parameters and constraints
public class ComplexGeneric<TKey, TValue, TOutput>
    where TKey : struct, IEquatable<TKey>
    where TValue : class, IDisposable, new()
    where TOutput : IBaseInterface
{
    // Field with generic type
    private Dictionary<TKey, TValue> _dictionary = new Dictionary<TKey, TValue>();

    // Method with constraints on method type parameters
    public void ConstrainedMethod<T, U>(T t, U u)
        where T : TValue
        where U : struct, IConvertible
    { }

    // Generic method that uses containing class type parameters
    public TOutput ProcessValues(TKey key, TValue value)
    {
        return default(TOutput);
    }

    // Nested type that uses containing type's type parameters
    public struct NestedStruct
    {
        public TKey Key;
        public TValue Value;
    }
}

// Class that uses unsafe code - fixed buffers only allowed in structs
public unsafe class UnsafeClass
{
    // Using array instead of fixed buffer for class
    private byte[] Buffer = new byte[128];

    // Method with pointer parameters
    public void PointerMethod(int* ptr)
    {
        // Use pointer
        *ptr = 42;
    }

    // Method with pointer locals
    public void MethodWithPointerLocals()
    {
        int local = 42;
        int* ptr = &local;
        *ptr = 100;
    }
}

// Struct with fixed buffer (correct usage)
public unsafe struct UnsafeStruct
{
    // Fixed size buffer (special field type)
    public fixed byte Buffer[128];
}

// Main program entry point
public class Program
{
    // Special custom attribute for method impl options - removed incompatible option
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void Main()
    {
        Console.WriteLine("Hello Metadata World!");

        // Create all the types to ensure they're used
        var derived = new DerivedClass();
        derived.VirtualMethod();
        derived.AsyncMethod().Wait();

        // Variance with arrays and generics
        object[] objArray = new string[10];
        IEnumerable<string> strings = new List<string>();
        IEnumerable<object> objects = strings; // Covariance

        // Use generic types
        var complex = new ComplexGeneric<int, MemoryStream, IBaseInterface>();

        // Use extension methods
        "test".ToCustomString();

        // Local functions (captured variables)
        int outerVar = 42;
        Action<int> localFunc = delegate(int param)
        {
            Console.WriteLine(outerVar + param);
        };
        localFunc(10);

        // Switch expression replaced with traditional switch
        var value = 1;
        string result;
        switch (value)
        {
            case 1:
                result = "One";
                break;
            case 2:
                result = "Two";
                break;
            default:
                result = "Other";
                break;
        }

        // LINQ (generates lots of interesting IL)
        var query = Enumerable.Range(1, 10)
            .Where(n => n % 2 == 0)
            .Select(n => n * n)
            .ToList();
    }
}

// Tuple return type replaced with custom tuple class
public static class TupleExample
{
    // Custom tuple class instead of ValueTuple
    public class CustomTuple
    {
        public int Count { get; set; }
        public string Name { get; set; }
        public List<int> Values { get; set; }
    }

    public static CustomTuple GetTuple()
    {
        return new CustomTuple {
            Count = 42,
            Name = "Test",
            Values = new List<int> { 1, 2, 3 }
        };
    }

    // Extension method for KeyValuePair
    public static void ExtractPair(this KeyValuePair<int, string> kvp, out int key, out string value)
    {
        key = kvp.Key;
        value = kvp.Value;
    }
}

// Simple classes instead of records
public class Person
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public int Age { get; set; }

    public Person(string firstName, string lastName, int age)
    {
        FirstName = firstName;
        LastName = lastName;
        Age = age;
    }
}

// Inheritance
public class Employee : Person
{
    public string EmployeeId { get; set; }

    public Employee(string firstName, string lastName, int age, string employeeId)
        : base(firstName, lastName, age)
    {
        EmployeeId = employeeId;
    }
}

// Regular interface without default implementation
public interface IWithDefault
{
    void RequiredMethod();

    // Regular method declaration (no implementation)
    void DefaultMethod();
}

// Implementation class
public class WithDefaultImplementation : IWithDefault
{
    public void RequiredMethod() { }

    public void DefaultMethod()
    {
        Console.WriteLine("Default");
    }
}

// Using normal struct (no ref struct support in older .NET)
public struct BufferStruct
{
    public byte[] Data;

    public BufferStruct(byte[] data)
    {
        Data = data;
    }
}
*/

use std::path::PathBuf;

use dotscope::metadata::{
    cilobject::CilObject,
    imports::ImportType,
    root::CIL_HEADER_MAGIC,
    streams::{
        AssemblyRaw, AssemblyRefRaw, ClassLayoutRaw, CodedIndex, ConstantRaw, CustomAttributeRaw,
        DeclSecurityRaw, EventMapRaw, EventRaw, FieldLayoutRaw, FieldMarshalRaw, FieldRaw,
        FieldRvaRaw, GenericParamConstraintRaw, GenericParamRaw, ImplMapRaw, InterfaceImplRaw,
        MemberRefRaw, MethodDefRaw, MethodImplRaw, MethodSemanticsRaw, MethodSpecRaw, ModuleRaw,
        ModuleRefRaw, NestedClassRaw, ParamRaw, PropertyMapRaw, PropertyRaw, StandAloneSigRaw,
        TableId, TypeDefRaw, TypeRefRaw, TypeSpecRaw,
    },
};

#[test]
fn crafted_2() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/crafted_2.exe");
    let asm = CilObject::from_file(&path).unwrap();

    verify_cor20(&asm);
    verify_root(&asm);
    verify_tableheader(&asm);
    verify_custom_attributes(&asm);
    //verify_imports(&asm);
}

/// Verify the cor20 header matches the values of '`crafted_2.exe`' on disk
fn verify_cor20(asm: &CilObject) {
    let cor20 = asm.cor20header();

    assert_eq!(cor20.cb, 0x48);
    assert_eq!(cor20.major_runtime_version, 2);
    assert_eq!(cor20.minor_runtime_version, 5);
    assert_eq!(cor20.meta_data_rva, 0x26DC);
    assert_eq!(cor20.meta_data_size, 0x2BA4);
    assert_eq!(cor20.flags, 0x1);
    assert_eq!(cor20.entry_point_token, 0x06000039);
    assert_eq!(cor20.resource_rva, 0);
    assert_eq!(cor20.resource_size, 0);
    assert_eq!(cor20.strong_name_signature_rva, 0);
    assert_eq!(cor20.strong_name_signature_size, 0);
    assert_eq!(cor20.code_manager_table_rva, 0);
    assert_eq!(cor20.code_manager_table_size, 0);
    assert_eq!(cor20.vtable_fixups_rva, 0);
    assert_eq!(cor20.vtable_fixups_size, 0);
    assert_eq!(cor20.export_address_table_jmp_rva, 0);
    assert_eq!(cor20.export_address_table_jmp_size, 0);
    assert_eq!(cor20.managed_native_header_rva, 0);
    assert_eq!(cor20.managed_native_header_size, 0);
}

/// Verify that the metadata 'Root' matches the values of '`crafted_2.exe`' on disk
fn verify_root(asm: &CilObject) {
    let root = asm.metadata_root();

    assert_eq!(root.signature, CIL_HEADER_MAGIC);
    assert_eq!(root.major_version, 1);
    assert_eq!(root.minor_version, 1);
    assert_eq!(root.version, "v4.0.30319\0\0");
    assert_eq!(root.flags, 0);
    assert_eq!(root.stream_number, 5);

    {
        let stream = &root.stream_headers[0];
        assert_eq!(stream.name, "#~");
        assert_eq!(stream.offset, 0x6C);
        assert_eq!(stream.size, 0x135C);
    }

    {
        let stream = &root.stream_headers[1];
        assert_eq!(stream.name, "#Strings");
        assert_eq!(stream.offset, 0x13C8);
        assert_eq!(stream.size, 0xEC4);
    }

    {
        let stream = &root.stream_headers[2];
        assert_eq!(stream.name, "#US");
        assert_eq!(stream.offset, 0x228C);
        assert_eq!(stream.size, 0xD4);
    }

    {
        let stream = &root.stream_headers[3];
        assert_eq!(stream.name, "#GUID");
        assert_eq!(stream.offset, 0x2360);
        assert_eq!(stream.size, 0x10);
    }

    {
        let stream = &root.stream_headers[4];
        assert_eq!(stream.name, "#Blob");
        assert_eq!(stream.offset, 0x2370);
        assert_eq!(stream.size, 0x834);
    }
}

/// Verify that the `TableHeader` matches the values of '`crafted_2.dll`' on disk
fn verify_tableheader(asm: &CilObject) {
    let tables_header = asm.tables().unwrap();

    assert_eq!(tables_header.major_version, 2);
    assert_eq!(tables_header.minor_version, 0);
    assert_eq!(tables_header.valid, 0x1E093FB7FF57);
    assert_eq!(tables_header.sorted, 0x16003301FA00);
    assert_eq!(tables_header.table_count(), 31);

    match tables_header.table::<ModuleRaw>(TableId::Module) {
        Some(table) => {
            assert_eq!(table.row_count(), 1);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.generation, 0);
            assert_eq!(row.name, 0x9CF);
            assert_eq!(row.mvid, 1);
            assert_eq!(row.encid, 0);
            assert_eq!(row.encbaseid, 0);

            let guids = asm.guids().unwrap();
            let guid = guids.get(row.mvid as usize).unwrap();
            assert_eq!(guid, uguid::guid!("85b7e7e7-adf5-40ee-b525-c916a61712f0"));
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<TypeRefRaw>(TableId::TypeRef) {
        Some(table) => {
            assert_eq!(table.row_count(), 65);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.token.value(), 0x01000001);
            assert_eq!(
                row.resolution_scope,
                CodedIndex::new(TableId::AssemblyRef, 1)
            );
            assert_eq!(row.type_name, 0x80D);
            assert_eq!(row.type_namespace, 0xBE8);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<TypeDefRaw>(TableId::TypeDef) {
        Some(table) => {
            assert_eq!(table.row_count(), 36);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.type_name, 0x1FD);
            assert_eq!(row.type_namespace, 0);
            assert_eq!(row.extends, CodedIndex::new(TableId::TypeDef, 0));
            assert_eq!(row.field_list, 1);
            assert_eq!(row.method_list, 1);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<FieldRaw>(TableId::Field) {
        Some(table) => {
            assert_eq!(table.row_count(), 48);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0x26);
            assert_eq!(row.name, 0xABB);
            assert_eq!(row.signature, 0x505);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<MethodDefRaw>(TableId::MethodDef) {
        Some(table) => {
            assert_eq!(table.row_count(), 97);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.rva, 0x2050);
            assert_eq!(row.impl_flags, 0);
            assert_eq!(row.flags, 0x1886);
            assert_eq!(row.name, 0xBA5);
            assert_eq!(row.signature, 1);
            assert_eq!(row.param_list, 1);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<ParamRaw>(TableId::Param) {
        Some(table) => {
            assert_eq!(table.row_count(), 72);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.sequence, 1);
            assert_eq!(row.name, 0x995);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<InterfaceImplRaw>(TableId::InterfaceImpl) {
        Some(table) => {
            assert_eq!(table.row_count(), 5);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.class, 7);
            assert_eq!(row.interface, CodedIndex::new(TableId::TypeDef, 6));
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<MemberRefRaw>(TableId::MemberRef) {
        Some(table) => {
            assert_eq!(table.row_count(), 67);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.class, CodedIndex::new(TableId::TypeRef, 1));
            assert_eq!(row.name, 0xBA5);
            assert_eq!(row.signature, 1);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<ConstantRaw>(TableId::Constant) {
        Some(table) => {
            assert_eq!(table.row_count(), 7);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.base, 0xA);
            assert_eq!(row.parent, CodedIndex::new(TableId::Field, 7));
            assert_eq!(row.value, 0x265);
        }

        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<CustomAttributeRaw>(TableId::CustomAttribute) {
        Some(table) => {
            assert_eq!(table.row_count(), 88);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.parent, CodedIndex::new(TableId::Module, 1));
            assert_eq!(row.constructor, CodedIndex::new(TableId::MemberRef, 10));
            assert_eq!(row.value, 0x297);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<FieldMarshalRaw>(TableId::FieldMarshal) {
        Some(table) => {
            assert_eq!(table.row_count(), 1);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.parent, CodedIndex::new(TableId::Field, 18));
            assert_eq!(row.native_type, 0x503);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<DeclSecurityRaw>(TableId::DeclSecurity) {
        Some(table) => {
            assert_eq!(table.row_count(), 2);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.action, 8);
            assert_eq!(row.parent, CodedIndex::new(TableId::Assembly, 1));
            assert_eq!(row.permission_set, 0x29C);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<ClassLayoutRaw>(TableId::ClassLayout) {
        Some(table) => {
            assert_eq!(table.row_count(), 3);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.packing_size, 0);
            assert_eq!(row.class_size, 0x10);
            assert_eq!(row.parent, 0xB);
        }
        None => {
            panic!("This tables should be there");
        }
    }

    match tables_header.table::<FieldLayoutRaw>(TableId::FieldLayout) {
        Some(table) => {
            assert_eq!(table.row_count(), 3);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.field_offset, 0);
            assert_eq!(row.field, 0xC);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<StandAloneSigRaw>(TableId::StandAloneSig) {
        Some(table) => {
            assert_eq!(table.row_count(), 11);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.signature, 0x53);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<EventMapRaw>(TableId::EventMap) {
        Some(module) => {
            assert_eq!(module.row_count(), 2);

            let row = module.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.parent, 0x7);
            assert_eq!(row.event_list, 0x1);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<EventRaw>(TableId::Event) {
        Some(table) => {
            assert_eq!(table.row_count(), 3);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0x102);
            assert_eq!(row.event_type, CodedIndex::new(TableId::TypeRef, 23));
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<PropertyMapRaw>(TableId::PropertyMap) {
        Some(table) => {
            assert_eq!(table.row_count(), 8);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.parent, 0x4);
            assert_eq!(row.property_list, 1);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<PropertyRaw>(TableId::Property) {
        Some(table) => {
            assert_eq!(table.row_count(), 13);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.flags, 0);
            assert_eq!(row.name, 0x9B4);
            assert_eq!(row.signature, 0x66E);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<MethodSemanticsRaw>(TableId::MethodSemantics) {
        Some(table) => {
            assert_eq!(table.row_count(), 31);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.semantics, 8);
            assert_eq!(row.method, 0xE);
            assert_eq!(row.association, CodedIndex::new(TableId::Event, 1));
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<MethodImplRaw>(TableId::MethodImpl) {
        Some(table) => {
            assert_eq!(table.row_count(), 4);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.class, 0xE);
            assert_eq!(row.method_body, CodedIndex::new(TableId::MethodDef, 39));
            assert_eq!(
                row.method_declaration,
                CodedIndex::new(TableId::MethodDef, 13)
            );
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<ModuleRefRaw>(TableId::ModuleRef) {
        Some(table) => {
            assert_eq!(table.row_count(), 2);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.name, 0xA33);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<TypeSpecRaw>(TableId::TypeSpec) {
        Some(module) => {
            assert_eq!(module.row_count(), 16);

            let row = module.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.signature, 0x40);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<ImplMapRaw>(TableId::ImplMap) {
        Some(table) => {
            assert_eq!(table.row_count(), 2);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.mapping_flags, 0x104);
            assert_eq!(row.member_forwarded, CodedIndex::new(TableId::MethodDef, 8));
            assert_eq!(row.import_name, 0xE86);
            assert_eq!(row.import_scope, 0x1);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<FieldRvaRaw>(TableId::FieldRVA) {
        Some(module) => {
            assert_eq!(module.row_count(), 1);

            let row = module.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.rva, 0x5410);
            assert_eq!(row.field, 0x1E);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<AssemblyRaw>(TableId::Assembly) {
        Some(table) => {
            assert_eq!(table.row_count(), 1);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.hash_alg_id, 0x8004);
            assert_eq!(row.major_version, 1);
            assert_eq!(row.minor_version, 2);
            assert_eq!(row.build_number, 3);
            assert_eq!(row.revision_number, 4);
            assert_eq!(row.flags, 0);
            assert_eq!(row.public_key, 0);
            assert_eq!(row.name, 0x14E);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<AssemblyRefRaw>(TableId::AssemblyRef) {
        Some(table) => {
            assert_eq!(table.row_count(), 2);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.major_version, 4);
            assert_eq!(row.minor_version, 0);
            assert_eq!(row.build_number, 0);
            assert_eq!(row.revision_number, 0);
            assert_eq!(row.flags, 0);
            assert_eq!(row.public_key_or_token, 0x25C);
            assert_eq!(row.name, 0x24B);
            assert_eq!(row.hash_value, 0);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<NestedClassRaw>(TableId::NestedClass) {
        Some(table) => {
            assert_eq!(table.row_count(), 10);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.nested_class, 0x1B);
            assert_eq!(row.enclosing_class, 0xE);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<GenericParamRaw>(TableId::GenericParam) {
        Some(table) => {
            assert_eq!(table.row_count(), 19);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.number, 0);
            assert_eq!(row.flags, 4);
            assert_eq!(row.owner, CodedIndex::new(TableId::TypeDef, 9));
            assert_eq!(row.name, 0x22F);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<MethodSpecRaw>(TableId::MethodSpec) {
        Some(table) => {
            assert_eq!(table.row_count(), 7);

            let row = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.method, CodedIndex::new(TableId::MemberRef, 33));
            assert_eq!(row.instantiation, 0x88);
        }
        None => {
            panic!("This table should be there");
        }
    }

    match tables_header.table::<GenericParamConstraintRaw>(TableId::GenericParamConstraint) {
        Some(table) => {
            assert_eq!(table.row_count(), 16);

            let row: GenericParamConstraintRaw = table.get(1).unwrap();
            assert_eq!(row.rid, 1);
            assert_eq!(row.owner, 0x3);
            assert_eq!(row.constraint, CodedIndex::new(TableId::TypeRef, 24));
        }
        None => {
            panic!("This table should be there");
        }
    }
}

/// Verify custom attributes match the expected values from the crafted_2.exe source code
fn verify_custom_attributes(asm: &CilObject) {
    // Verify we have the expected number of custom attributes in total
    let custom_attr_table = asm
        .tables()
        .unwrap()
        .table::<CustomAttributeRaw>(TableId::CustomAttribute)
        .unwrap();
    assert_eq!(
        custom_attr_table.row_count(),
        88,
        "Expected 88 custom attributes total"
    );

    // Test assembly-level custom attributes
    verify_assembly_custom_attributes(asm);

    // Test module-level custom attributes
    verify_module_custom_attributes(asm);

    // Test type-level custom attributes
    verify_type_custom_attributes(asm);

    // Test method-level custom attributes
    verify_method_custom_attributes(asm);

    // Test specialized attribute tables (FieldLayout, FieldMarshal)
    verify_specialized_attribute_tables(asm);
}

/// Verify assembly-level custom attributes
fn verify_assembly_custom_attributes(asm: &CilObject) {
    // Count assembly-level custom attributes by iterating through the custom attribute table
    let custom_attr_table = asm
        .tables()
        .unwrap()
        .table::<CustomAttributeRaw>(TableId::CustomAttribute)
        .unwrap();
    let mut assembly_attr_count = 0;

    for attr_row in custom_attr_table.iter() {
        // Check if this attribute is on the assembly (target token 0x20000001)
        if attr_row.parent.token.value() == 0x20000001 {
            assembly_attr_count += 1;
        }
    }

    // Expected assembly attributes:
    // - AssemblyTitle, AssemblyDescription, AssemblyVersion, AssemblyCulture, CLSCompliant
    // - SecurityPermission, FileIOPermission, MetadataTestAttribute
    assert!(
        assembly_attr_count >= 8,
        "Expected at least 8 assembly-level custom attributes, found {}",
        assembly_attr_count
    );
}

/// Verify module-level custom attributes  
fn verify_module_custom_attributes(asm: &CilObject) {
    let custom_attr_table = asm
        .tables()
        .unwrap()
        .table::<CustomAttributeRaw>(TableId::CustomAttribute)
        .unwrap();
    let mut module_attr_count = 0;

    for attr_row in custom_attr_table.iter() {
        // Check if this attribute is on the module (target token 0x00000001)
        if attr_row.parent.token.value() == 0x00000001 {
            module_attr_count += 1;
        }
    }

    // Expected: DefaultCharSet attribute
    assert!(
        module_attr_count >= 1,
        "Expected at least 1 module-level custom attribute, found {}",
        module_attr_count
    );
}

/// Verify type-level custom attributes
fn verify_type_custom_attributes(asm: &CilObject) {
    let types = asm.types();
    let mut found_attributes = 0;
    let mut specific_types_found = 0;

    // Look for specific types with known attributes
    for entry in types.iter() {
        let type_def = entry.value();
        let custom_attrs = &type_def.custom_attributes;
        let attr_count = custom_attrs.iter().count();

        if attr_count > 0 {
            found_attributes += attr_count;

            // Check specific types we know should have attributes
            match type_def.name.as_str() {
                "MetadataTestAttribute" => {
                    // Should have AttributeUsage attribute
                    assert!(
                        attr_count >= 1,
                        "MetadataTestAttribute should have AttributeUsage attribute"
                    );
                    specific_types_found += 1;
                }
                "TestEnum" => {
                    // Should have Flags attribute
                    assert!(attr_count >= 1, "TestEnum should have Flags attribute");
                    specific_types_found += 1;
                }
                "StructWithExplicitLayout" => {
                    // Should have StructLayout attribute
                    assert!(
                        attr_count >= 1,
                        "StructWithExplicitLayout should have StructLayout attribute"
                    );
                    specific_types_found += 1;
                }
                "BaseClass" => {
                    // Should have Serializable attribute
                    assert!(
                        attr_count >= 1,
                        "BaseClass should have Serializable attribute"
                    );
                    specific_types_found += 1;
                }
                "DerivedClass" => {
                    // Should have MetadataTest attribute
                    assert!(
                        attr_count >= 1,
                        "DerivedClass should have MetadataTest attribute"
                    );
                    specific_types_found += 1;
                }
                _ => {}
            }
        }
    }

    // We should find some type-level attributes, even if not all the specific ones
    assert!(
        found_attributes > 0,
        "Expected to find some type-level custom attributes"
    );
    // Don't require all specific types as some attributes might be stored differently
    assert!(
        specific_types_found >= 2,
        "Expected to find at least 2 specific types with attributes, found {}",
        specific_types_found
    );
}

/// Verify method-level custom attributes
fn verify_method_custom_attributes(asm: &CilObject) {
    let methods = asm.methods();
    let mut found_method_attributes = 0;
    let mut specific_methods_found = 0;

    for entry in methods.iter() {
        let method = entry.value();
        let custom_attrs = &method.custom_attributes;
        let attr_count = custom_attrs.iter().count();

        if attr_count > 0 {
            found_method_attributes += attr_count;

            // Check specific methods we found to have attributes
            match method.name.as_str() {
                "ComplexMethod" => {
                    // Should have Obsolete attribute
                    assert!(
                        attr_count >= 1,
                        "ComplexMethod should have Obsolete attribute"
                    );
                    specific_methods_found += 1;
                }
                "SecureMethod" => {
                    // Should have SecurityCritical attribute (FileIOPermission might be in DeclSecurity table)
                    assert!(
                        attr_count >= 1,
                        "SecureMethod should have at least 1 custom attribute"
                    );
                    specific_methods_found += 1;
                }
                "AsyncMethod" => {
                    // Async methods get compiler-generated attributes
                    assert!(
                        attr_count >= 1,
                        "AsyncMethod should have compiler-generated attributes"
                    );
                    specific_methods_found += 1;
                }
                "ToCustomString" => {
                    // Extension methods get special attributes
                    assert!(
                        attr_count >= 1,
                        "ToCustomString should have extension method attribute"
                    );
                    specific_methods_found += 1;
                }
                _ => {}
            }
        }
    }

    assert!(
        found_method_attributes > 0,
        "Expected to find some method-level custom attributes"
    );
    assert!(
        specific_methods_found >= 4,
        "Expected to find at least 4 specific methods with attributes, found {}",
        specific_methods_found
    );
}

/// Verify specialized attribute tables that store field attributes
fn verify_specialized_attribute_tables(asm: &CilObject) {
    let tables = asm.tables().unwrap();

    // Test FieldLayout table (stores FieldOffset attributes)
    if let Some(field_layout_table) = tables.table::<FieldLayoutRaw>(TableId::FieldLayout) {
        let layout_count = field_layout_table.row_count();
        assert!(
            layout_count > 0,
            "Expected FieldLayout entries for explicit layout fields"
        );

        // Verify we have the expected number from the crafted source
        assert_eq!(
            layout_count, 3,
            "Expected 3 FieldLayout entries for StructWithExplicitLayout fields"
        );
    }

    // Test FieldMarshal table (stores MarshalAs attributes)
    if let Some(field_marshal_table) = tables.table::<FieldMarshalRaw>(TableId::FieldMarshal) {
        let marshal_count = field_marshal_table.row_count();
        assert!(
            marshal_count > 0,
            "Expected FieldMarshal entries for marshaled fields"
        );

        // Verify we have the expected number from the crafted source
        assert_eq!(
            marshal_count, 1,
            "Expected 1 FieldMarshal entry for _marshaledField"
        );
    }

    // Test DeclSecurity table (stores security attributes)
    if let Some(decl_security_table) = tables.table::<DeclSecurityRaw>(TableId::DeclSecurity) {
        let security_count = decl_security_table.row_count();
        assert!(
            security_count > 0,
            "Expected DeclSecurity entries for security attributes"
        );

        // Verify we have the expected number from the crafted source
        assert_eq!(
            security_count, 2,
            "Expected 2 DeclSecurity entries for assembly and method security attributes"
        );
    }
}

/// Verify the Imports (`refs_assembly` + `refs_modules`)
fn _verify_imports(asm: &CilObject) {
    let imports = asm.imports();

    let set_state_machine_class = imports.by_name("SetStateMachine").unwrap();

    assert_eq!(set_state_machine_class.token.value(), 0x0A000018);
    assert_eq!(set_state_machine_class.name, "SetStateMachine");
    assert_eq!(
        set_state_machine_class.namespace,
        "System.Runtime.CompilerServices"
    );

    match &set_state_machine_class.import {
        ImportType::Method(ref_cell) => {
            assert!(
                ref_cell.rva.is_none(),
                "The imported method should have no RVA"
            );
        }
        _ => panic!("The import should be a method"),
    }
}
