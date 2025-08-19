//! Integration tests for high-level builder combinations.
//!
//! This module tests realistic scenarios where multiple builders are used together
//! to create complete .NET types with properties, events, and methods.

use dotscope::{prelude::*, Result};
use std::path::PathBuf;

fn get_test_context() -> Result<BuilderContext> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples/WindowsBase.dll");
    let view = CilAssemblyView::from_file(&path)?;
    let assembly = CilAssembly::new(view);
    Ok(BuilderContext::new(assembly))
}

/// Test creating a complete MVVM ViewModel class with properties and events.
/// This simulates a realistic .NET development scenario.
#[test]
fn test_mvvm_viewmodel_with_properties_and_events() -> Result<()> {
    let mut context = get_test_context()?;

    // Create a complete ViewModel class similar to:
    // public class PersonViewModel {
    //     public string Name { get; set; }
    //     public int Age { get; set; }
    // }
    let viewmodel_token = ClassBuilder::new("PersonViewModel")
        .public()
        .namespace("MyApp.ViewModels")
        // Add properties
        .auto_property("Name", TypeSignature::String)
        .auto_property("Age", TypeSignature::I4)
        // Add OnPropertyChanged method
        .method(|method| {
            method
                .public()
                .parameter("propertyName", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation that just returns
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        // Add default constructor
        .default_constructor()
        .build(&mut context)?;

    // Verify the class was created successfully
    assert_eq!(viewmodel_token.value() & 0xFF000000, 0x02000000); // TypeDef table

    Ok(())
}

/// Test creating a data model class with validation properties and events.
/// This demonstrates complex property patterns with backing logic.
#[test]
fn test_data_model_with_validation() -> Result<()> {
    let mut context = get_test_context()?;

    // Create a data model similar to:
    // public class Customer {
    //     public string Name { get; set; }
    // }
    let customer_token = ClassBuilder::new("Customer")
        .public()
        .namespace("MyApp.Models")
        // Add auto property
        .auto_property("Name", TypeSignature::String)
        // Add validation method
        .method(|method| {
            method
                .private()
                .parameter("propertyName", TypeSignature::String)
                .parameter("value", TypeSignature::Object)
                .returns(TypeSignature::Boolean)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple validation - just return true
                        asm.ldc_i4_1()? // Load true
                            .ret()?;
                        Ok(())
                    })
                })
        })
        .build(&mut context)?;

    assert_eq!(customer_token.value() & 0xFF000000, 0x02000000);

    Ok(())
}

/// Test creating a complete business service class with events and methods.
/// This demonstrates service-oriented architecture patterns.
#[test]
fn test_business_service_with_events() -> Result<()> {
    let mut context = get_test_context()?;

    // Create a service similar to:
    // public class CustomerService {
    //     public void AddCustomer(Customer customer) { ... }
    //     public void UpdateCustomer(Customer customer) { ... }
    //     private void OnCustomerAdded(Customer customer) { ... }
    // }
    let service_token = ClassBuilder::new("CustomerService")
        .public()
        .namespace("MyApp.Services")
        // Add business methods
        .method(|method| {
            method
                .public()
                .parameter("customer", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple method implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .public()
                .parameter("customer", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple method implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        // Add private helper method
        .method(|method| {
            method
                .private()
                .parameter("customer", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple helper method
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut context)?;

    assert_eq!(service_token.value() & 0xFF000000, 0x02000000);

    Ok(())
}

/// Test creating a class with inheritance, implementing common .NET patterns.
/// This tests that ClassBuilder works with inheritance scenarios.
#[test]
fn test_inherited_class_with_virtual_properties() -> Result<()> {
    let mut context = get_test_context()?;

    // First create a base class
    let base_token = ClassBuilder::new("BaseEntity")
        .public()
        .abstract_class()
        .namespace("MyApp.Entities")
        // Add ID property
        .auto_property("Id", TypeSignature::I4)
        // Add additional property
        .auto_property("Name", TypeSignature::String)
        // Add virtual method
        .method(|method| {
            method
                .public()
                .virtual_method()
                .returns(TypeSignature::Boolean)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ldc_i4_1()? // Return true by default
                            .ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut context)?;

    // Create derived class with inheritance using CodedIndex
    let base_coded_index = CodedIndex::new(
        TableId::TypeDef,
        base_token.row(),
        CodedIndexType::TypeDefOrRef,
    );
    let derived_token = ClassBuilder::new("Customer")
        .public()
        .namespace("MyApp.Entities")
        .inherits(base_coded_index) // Inherit from BaseEntity
        // Add additional properties
        .auto_property("Email", TypeSignature::String)
        .auto_property("IsActive", TypeSignature::Boolean)
        // Override virtual method
        .method(|method| {
            method
                .public()
                .virtual_method()
                .returns(TypeSignature::Boolean)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple validation logic
                        asm.ldc_i4_1()? // Return true
                            .ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut context)?;

    assert_eq!(base_token.value() & 0xFF000000, 0x02000000);
    assert_eq!(derived_token.value() & 0xFF000000, 0x02000000);

    Ok(())
}

/// Test creating multiple related classes that interact through events.
/// This simulates a complete event-driven system architecture.
#[test]
fn test_event_driven_architecture() -> Result<()> {
    let mut context = get_test_context()?;

    // Create Publisher class
    let publisher_token = ClassBuilder::new("EventPublisher")
        .public()
        .namespace("MyApp.Events")
        .field("DataChanged", TypeSignature::Object)
        .method(|method| {
            method
                .public()
                .parameter("data", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut context)?;

    // Create Subscriber class
    let subscriber_token = ClassBuilder::new("EventSubscriber")
        .public()
        .namespace("MyApp.Events")
        .auto_property("LastData", TypeSignature::Object)
        .method(|method| {
            method
                .public()
                .parameter("sender", TypeSignature::Object)
                .parameter("data", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .public()
                .parameter("publisher", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut context)?;

    // Create Coordinator class that uses both
    let coordinator_token = ClassBuilder::new("EventCoordinator")
        .public()
        .namespace("MyApp.Events")
        .auto_property("Publisher", TypeSignature::Object)
        .auto_property("Subscriber", TypeSignature::Object)
        .method(|method| {
            method.public().implementation(|body| {
                body.implementation(|asm| {
                    // Simple implementation
                    asm.ret()?;
                    Ok(())
                })
            })
        })
        .default_constructor()
        .build(&mut context)?;

    assert_eq!(publisher_token.value() & 0xFF000000, 0x02000000);
    assert_eq!(subscriber_token.value() & 0xFF000000, 0x02000000);
    assert_eq!(coordinator_token.value() & 0xFF000000, 0x02000000);

    Ok(())
}

/// Test creating a complex class with all builder types combined.
/// This is the ultimate integration test showing all features working together.
#[test]
fn test_ultimate_integration_all_builders() -> Result<()> {
    let mut context = get_test_context()?;

    // Create the most comprehensive class possible using all builders
    let ultimate_token = ClassBuilder::new("UltimateClass")
        .public()
        .namespace("MyApp.Ultimate")
        // Multiple auto-properties
        .auto_property("Id", TypeSignature::I4)
        .auto_property("Name", TypeSignature::String)
        .auto_property("IsEnabled", TypeSignature::Boolean)
        // Additional computed property
        .readonly_property("DisplayName", TypeSignature::String)
        // Read-only property
        .readonly_property("CreatedAt", TypeSignature::Object)
        // Multiple event fields
        .field("PropertyChanged", TypeSignature::Object)
        .field("StatusUpdated", TypeSignature::Object)
        // Various methods with different patterns
        .method(|method| {
            method
                .public()
                .parameter("newStatus", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .protected()
                .parameter("propertyName", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .private()
                .parameter("status", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        // Static method
        .method(|method| {
            method
                .public()
                .static_method()
                .returns(TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ldnull()? // Return null for simplicity
                            .ret()?;
                        Ok(())
                    })
                })
        })
        // Default constructor
        .default_constructor()
        .build(&mut context)?;

    assert_eq!(ultimate_token.value() & 0xFF000000, 0x02000000);

    Ok(())
}
