//! Reflection-based method invocation testing
//!
//! This module generates and executes C# test programs that use .NET reflection
//! to invoke methods in dotscope-modified assemblies. This validates that methods
//! added or modified by dotscope are correctly callable at runtime.

use crate::prelude::*;
use crate::test::mono::compilation::CSharpCompiler;
use crate::test::mono::execution::MonoRuntime;
use std::path::Path;

/// Dynamic test program builder using reflection
pub struct ReflectionTestBuilder {
    assembly_path: Option<String>,
    test_cases: Vec<TestCase>,
    custom_using_statements: Vec<String>,
    custom_setup_code: Vec<String>,
    expected_exit_code: i32,
}

impl Default for ReflectionTestBuilder {
    fn default() -> Self {
        Self {
            assembly_path: None,
            test_cases: Vec::new(),
            custom_using_statements: vec!["System".to_string(), "System.Reflection".to_string()],
            custom_setup_code: Vec::new(),
            expected_exit_code: 0,
        }
    }
}

impl ReflectionTestBuilder {
    /// Create new reflection test builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the assembly path to test
    pub fn assembly_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.assembly_path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    /// Add a test case for method invocation
    pub fn test_method(self, method_name: &str) -> MethodTestBuilder {
        MethodTestBuilder::new(self, method_name.to_string())
    }

    /// Add custom using statement
    pub fn with_using(mut self, using_statement: &str) -> Self {
        self.custom_using_statements
            .push(using_statement.to_string());
        self
    }

    /// Add custom setup code to run before tests
    pub fn with_setup_code(mut self, code: &str) -> Self {
        self.custom_setup_code.push(code.to_string());
        self
    }

    /// Set expected exit code (default: 0 for success)
    pub fn expect_exit_code(mut self, code: i32) -> Self {
        self.expected_exit_code = code;
        self
    }

    /// Generate the complete test program source code
    pub fn generate_test_program(&self) -> String {
        let assembly_path = self
            .assembly_path
            .as_deref()
            .unwrap_or("ASSEMBLY_PATH_NOT_SET");

        let using_statements = self
            .custom_using_statements
            .iter()
            .map(|u| format!("using {};", u))
            .collect::<Vec<_>>()
            .join("\n");

        let setup_code = if self.custom_setup_code.is_empty() {
            String::new()
        } else {
            self.custom_setup_code.join("\n            ")
        };

        let test_code = self.generate_test_cases_code();

        format!(
            r#"
{using_statements}

class Program
{{
    static void Main()
    {{
        try
        {{
            // Use LoadFile instead of LoadFrom for better isolation.
            // LoadFile doesn't use the assembly resolution context which
            // causes issues when loading .NET Framework/modified assemblies
            // from a .NET 8 host application.
            Assembly assembly = Assembly.LoadFile(@"{assembly_path}");
            
            {setup_code}
            
            {test_code}
            
            Console.WriteLine("✅ All reflection tests PASSED!");
            Environment.Exit({expected_exit_code});
        }} 
        catch (Exception ex) 
        {{
            Console.WriteLine($"ERROR: {{ex.Message}}");
            Environment.Exit(1);
        }}
    }}
    
    {helper_methods}
}}
"#,
            using_statements = using_statements,
            assembly_path = assembly_path,
            setup_code = setup_code,
            test_code = test_code,
            expected_exit_code = self.expected_exit_code,
            helper_methods = self.generate_helper_methods()
        )
    }

    /// Generate test cases code
    fn generate_test_cases_code(&self) -> String {
        if self.test_cases.is_empty() {
            return "Console.WriteLine(\"No test cases defined\");".to_string();
        }

        let mut code = Vec::new();

        for (i, test_case) in self.test_cases.iter().enumerate() {
            code.push(format!(
                "            // Test case {}: {}",
                i + 1,
                test_case.description
            ));
            code.push(test_case.generate_code(i));
            code.push(String::new()); // Empty line between test cases
        }

        code.join("\n")
    }

    /// Generate helper methods
    fn generate_helper_methods(&self) -> String {
        r#"
    static MethodInfo FindMethod(Assembly assembly, string methodName)
    {
        Type[] types = assembly.GetTypes();
        foreach (Type type in types) 
        {
            foreach (MethodInfo method in type.GetMethods()) 
            {
                if (method.Name == methodName) 
                {
                    return method;
                }
            }
        }
        return null;
    }

    static void AssertEqual<T>(T expected, T actual, string testName)
    {
        if (!object.Equals(expected, actual))
        {
            throw new Exception($"{testName} FAILED: Expected {expected}, got {actual}");
        }
        Console.WriteLine($"  ✅ {testName} PASSED: {actual}");
    }

    static void AssertNotNull(object obj, string testName)
    {
        if (obj == null)
        {
            throw new Exception($"{testName} FAILED: Value was null");
        }
        Console.WriteLine($"  ✅ {testName} PASSED: Not null");
    }
"#
        .to_string()
    }

    /// Add a test case (internal method)
    fn add_test_case(&mut self, test_case: TestCase) {
        self.test_cases.push(test_case);
    }
}

/// Builder for individual method test cases
pub struct MethodTestBuilder {
    parent: ReflectionTestBuilder,
    method_name: String,
    parameters: Vec<ParameterValue>,
    expected_result: Option<ExpectedValue>,
    description: String,
    custom_validation: Option<String>,
}

impl MethodTestBuilder {
    fn new(parent: ReflectionTestBuilder, method_name: String) -> Self {
        Self {
            description: format!("Test method {}", method_name),
            parent,
            method_name,
            parameters: Vec::new(),
            expected_result: None,
            custom_validation: None,
        }
    }

    /// Set test description
    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Add parameter to method call
    pub fn parameter<T: Into<ParameterValue>>(mut self, value: T) -> Self {
        self.parameters.push(value.into());
        self
    }

    /// Add multiple parameters
    pub fn parameters<T: Into<ParameterValue>>(mut self, values: Vec<T>) -> Self {
        for value in values {
            self.parameters.push(value.into());
        }
        self
    }

    /// Set expected return value
    pub fn expect<T: Into<ExpectedValue>>(mut self, expected: T) -> Self {
        self.expected_result = Some(expected.into());
        self
    }

    /// Expect method to execute without throwing
    pub fn expect_no_throw(mut self) -> Self {
        self.custom_validation = Some("// Method executed without throwing".to_string());
        self
    }

    /// Add custom validation code
    pub fn with_custom_validation(mut self, code: &str) -> Self {
        self.custom_validation = Some(code.to_string());
        self
    }

    /// Finish building this test case and return to parent builder
    pub fn and(mut self) -> ReflectionTestBuilder {
        let test_case = TestCase {
            method_name: self.method_name,
            parameters: self.parameters,
            expected_result: self.expected_result,
            description: self.description,
            custom_validation: self.custom_validation,
        };

        self.parent.add_test_case(test_case);
        self.parent
    }

    /// Finish building and generate the test program
    pub fn build(self) -> String {
        self.and().generate_test_program()
    }
}

/// Test case for method invocation
#[derive(Debug, Clone)]
struct TestCase {
    method_name: String,
    parameters: Vec<ParameterValue>,
    expected_result: Option<ExpectedValue>,
    description: String,
    custom_validation: Option<String>,
}

impl TestCase {
    fn generate_code(&self, index: usize) -> String {
        let mut code = Vec::new();

        // Find method (with unique variable name)
        let var_suffix = format!("{}_{}", self.method_name.to_lowercase(), index);
        code.push(format!(
            "            MethodInfo method_{} = FindMethod(assembly, \"{}\");",
            var_suffix, self.method_name
        ));

        code.push(format!(
            "            AssertNotNull(method_{}, \"Method {} exists\");",
            var_suffix, self.method_name
        ));

        // Prepare parameters
        if !self.parameters.is_empty() {
            let params_code = self
                .parameters
                .iter()
                .map(|p| p.to_csharp_code())
                .collect::<Vec<_>>()
                .join(", ");

            code.push(format!(
                "            object[] params_{} = {{ {} }};",
                var_suffix, params_code
            ));
        } else {
            code.push(format!(
                "            object[] params_{} = null;",
                var_suffix
            ));
        }

        // Invoke method
        code.push(format!(
            "            object result_{} = method_{}.Invoke(null, params_{});",
            var_suffix, var_suffix, var_suffix
        ));

        // Validate result
        if let Some(expected) = &self.expected_result {
            code.push(
                expected
                    .generate_validation_code(&format!("result_{}", var_suffix), &self.description),
            );
        } else if let Some(custom) = &self.custom_validation {
            code.push(format!("            {}", custom));
        } else {
            code.push(format!(
                "            Console.WriteLine(\"  ✅ {} executed successfully\");",
                self.description
            ));
        }

        code.join("\n")
    }
}

/// Parameter value for method invocation
#[derive(Debug, Clone)]
pub enum ParameterValue {
    Int32(i32),
    String(String),
    Boolean(bool),
    Null,
    Custom(String), // Custom C# expression
}

impl ParameterValue {
    fn to_csharp_code(&self) -> String {
        match self {
            ParameterValue::Int32(i) => i.to_string(),
            ParameterValue::String(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            ParameterValue::Boolean(b) => if *b { "true" } else { "false" }.to_string(),
            ParameterValue::Null => "null".to_string(),
            ParameterValue::Custom(expr) => expr.clone(),
        }
    }
}

impl From<i32> for ParameterValue {
    fn from(value: i32) -> Self {
        ParameterValue::Int32(value)
    }
}

impl From<&str> for ParameterValue {
    fn from(value: &str) -> Self {
        ParameterValue::String(value.to_string())
    }
}

impl From<String> for ParameterValue {
    fn from(value: String) -> Self {
        ParameterValue::String(value)
    }
}

impl From<bool> for ParameterValue {
    fn from(value: bool) -> Self {
        ParameterValue::Boolean(value)
    }
}

/// Expected result for validation
#[derive(Debug, Clone)]
pub enum ExpectedValue {
    Int32(i32),
    String(String),
    Boolean(bool),
    Null,
    NotNull,
    Custom(String), // Custom validation expression
}

impl ExpectedValue {
    fn generate_validation_code(&self, result_var: &str, test_name: &str) -> String {
        match self {
            ExpectedValue::Int32(expected) => {
                format!(
                    "            AssertEqual({}, (int){}, \"{}\");",
                    expected, result_var, test_name
                )
            }
            ExpectedValue::String(expected) => {
                format!(
                    "            AssertEqual(\"{}\", (string){}, \"{}\");",
                    expected.replace('"', "\\\""),
                    result_var,
                    test_name
                )
            }
            ExpectedValue::Boolean(expected) => {
                format!(
                    "            AssertEqual({}, (bool){}, \"{}\");",
                    if *expected { "true" } else { "false" },
                    result_var,
                    test_name
                )
            }
            ExpectedValue::Null => {
                format!(
                    "            if ({} != null) throw new Exception(\"{} FAILED: Expected null, got \" + {});",
                    result_var, test_name, result_var
                )
            }
            ExpectedValue::NotNull => {
                format!(
                    "            AssertNotNull({}, \"{}\");",
                    result_var, test_name
                )
            }
            ExpectedValue::Custom(expr) => {
                format!("            {}", expr)
            }
        }
    }
}

impl From<i32> for ExpectedValue {
    fn from(value: i32) -> Self {
        ExpectedValue::Int32(value)
    }
}

impl From<&str> for ExpectedValue {
    fn from(value: &str) -> Self {
        ExpectedValue::String(value.to_string())
    }
}

impl From<String> for ExpectedValue {
    fn from(value: String) -> Self {
        ExpectedValue::String(value)
    }
}

impl From<bool> for ExpectedValue {
    fn from(value: bool) -> Self {
        ExpectedValue::Boolean(value)
    }
}

/// Reflection test executor
#[derive(Default)]
pub struct ReflectionTestExecutor {
    compiler: CSharpCompiler,
    runtime: MonoRuntime,
}

impl ReflectionTestExecutor {
    /// Create new test executor
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute reflection test program
    pub fn execute_test(
        &mut self,
        test_program: &str,
        temp_dir: &Path,
    ) -> Result<ReflectionTestResult> {
        // Compile test program
        // Use AnyCPU architecture for maximum compatibility across CI environments
        let test_exe_path = temp_dir.join("reflection_test.exe");
        let compilation_result = self.compiler.compile_executable(
            test_program,
            &test_exe_path,
            &super::runner::ArchConfig::anycpu(),
        )?;

        if !compilation_result.success {
            return Ok(ReflectionTestResult {
                compilation_success: false,
                execution_success: false,
                compilation_error: compilation_result.error,
                execution_output: String::new(),
                execution_error: None,
            });
        }

        // Set the appropriate runtime based on which compiler was used
        if let Some(ref compiler_type) = compilation_result.compiler_used {
            self.runtime
                .set_runtime(super::execution::RuntimeType::for_compiler(compiler_type));
        }

        // Execute test program using the actual output path (may be .dll for dotnet SDK)
        let actual_output_path = compilation_result.executable_path();
        let execution_result = self.runtime.execute_assembly(actual_output_path)?;

        Ok(ReflectionTestResult {
            compilation_success: true,
            execution_success: execution_result.success,
            compilation_error: None,
            execution_output: execution_result.stdout,
            execution_error: if execution_result.success {
                None
            } else {
                Some(execution_result.stderr)
            },
        })
    }

    /// Create and execute a complete reflection test
    pub fn create_and_execute_test<F>(
        &mut self,
        assembly_path: &Path,
        temp_dir: &Path,
        builder_fn: F,
    ) -> Result<ReflectionTestResult>
    where
        F: FnOnce(ReflectionTestBuilder) -> String,
    {
        let test_program = builder_fn(ReflectionTestBuilder::new().assembly_path(assembly_path));

        self.execute_test(&test_program, temp_dir)
    }
}

/// Result of executing a reflection test
#[derive(Debug)]
pub struct ReflectionTestResult {
    pub compilation_success: bool,
    pub execution_success: bool,
    pub compilation_error: Option<String>,
    pub execution_output: String,
    pub execution_error: Option<String>,
}

impl ReflectionTestResult {
    /// Check if test was completely successful
    pub fn is_successful(&self) -> bool {
        self.compilation_success && self.execution_success
    }

    /// Get error summary
    pub fn error_summary(&self) -> String {
        if let Some(comp_error) = &self.compilation_error {
            format!("Compilation failed: {}", comp_error)
        } else if let Some(exec_error) = &self.execution_error {
            format!("Execution failed: {}", exec_error)
        } else if !self.execution_success {
            "Execution failed with unknown error".to_string()
        } else {
            "No errors".to_string()
        }
    }

    /// Print formatted test results
    pub fn print_results(&self, test_name: &str) {
        if self.is_successful() {
            println!("      ✅ {} PASSED:", test_name);
            for line in self.execution_output.lines() {
                println!("         {}", line);
            }
        } else {
            println!("      ❌ {} FAILED:", test_name);
            if let Some(error) = &self.compilation_error {
                println!("         Compilation error: {}", error);
            } else if let Some(error) = &self.execution_error {
                println!("         Execution error: {}", error);
            }

            if !self.execution_output.is_empty() {
                println!("         Output: {}", self.execution_output);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test::mono::reflection::{
        ExpectedValue, ParameterValue, ReflectionTestBuilder, ReflectionTestResult,
    };

    #[test]
    fn test_reflection_test_builder() {
        let program = ReflectionTestBuilder::new()
            .assembly_path("/test/path.exe")
            .test_method("TestMethod")
            .parameter(5)
            .parameter("hello")
            .expect(42)
            .build();

        assert!(program.contains("Assembly.LoadFile"));
        assert!(program.contains("TestMethod"));
        assert!(program.contains("AssertEqual"));
    }

    #[test]
    fn test_parameter_values() {
        let int_param = ParameterValue::Int32(42);
        let string_param = ParameterValue::String("test".to_string());
        let bool_param = ParameterValue::Boolean(true);

        assert_eq!(int_param.to_csharp_code(), "42");
        assert_eq!(string_param.to_csharp_code(), "\"test\"");
        assert_eq!(bool_param.to_csharp_code(), "true");
    }

    #[test]
    fn test_expected_values() {
        let result_var = "result";
        let test_name = "Test";

        let int_expected = ExpectedValue::Int32(42);
        let validation = int_expected.generate_validation_code(result_var, test_name);
        assert!(validation.contains("AssertEqual(42"));
    }

    #[test]
    fn test_reflection_test_result() {
        let result = ReflectionTestResult {
            compilation_success: true,
            execution_success: true,
            compilation_error: None,
            execution_output: "Test passed".to_string(),
            execution_error: None,
        };

        assert!(result.is_successful());
        assert_eq!(result.error_summary(), "No errors");
    }
}
