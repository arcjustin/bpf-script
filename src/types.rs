use crate::error::{Error, Result};

use std::collections::HashMap;

/// Represents the physical properties of an integer.
#[derive(Clone, Copy, Debug, Default)]
pub struct Integer {
    /// The total number of bits used to store the integer.
    pub used_bits: u32,

    /// The number of bits used when performing operations, less than `used_bits`.
    pub bits: u32,

    /// Whether the integer is signed.
    pub is_signed: bool,
}

impl Integer {
    /// Returns the size of the integer in bytes.
    pub fn get_size(&self) -> u32 {
        self.used_bits / 8
    }
}

/// Represents the physical properties of a float.
#[derive(Clone, Copy, Debug, Default)]
pub struct Float {
    /// The number of bits used to store and perform operations on.
    pub bits: u32,
}

impl Float {
    /// Returns the size of the float in bytes.
    pub fn get_size(&self) -> u32 {
        self.bits / 8
    }
}

/// Represents the physical properties of an array.
#[derive(Clone, Copy, Debug, Default)]
pub struct Array {
    /// The type of element the array stores.
    pub element_type_id: usize,

    /// The number of elements in the array.
    pub num_elements: u32,

    /// Cached size.
    pub size: u32,
}

impl Array {
    /// Creates a new array referencing the given database.
    ///
    /// # Arguments
    ///
    /// * `database` - The database that contains the element type id.
    /// * `element_type_id` - The type id of the array elements.
    /// * `num_elements` - The number of elements in the array.
    pub fn create(
        database: &TypeDatabase,
        element_type_id: usize,
        num_elements: u32,
    ) -> Result<Self> {
        let element_type = database
            .get_type_by_id(element_type_id)
            .ok_or(Error::InvalidTypeId)?;
        let size = element_type.get_size() * num_elements;
        Ok(Self {
            element_type_id,
            num_elements,
            size,
        })
    }

    /// Returns the size of the array in bytes.
    pub fn get_size(&self) -> u32 {
        self.size
    }
}

/// Represents the phystical properties of a field in a struct or union.
#[derive(Clone, Copy, Debug, Default)]
pub struct Field {
    /// The offset, in bits, of the field.
    pub offset: u32,

    /// The type of the field.
    pub type_id: usize,
}

impl Field {
    /// Returns the field's type.
    ///
    /// # Arguments
    ///
    /// * `database` - The database containing this structure/field.
    pub fn get_type<'a>(&self, database: &'a TypeDatabase) -> Option<&'a Type> {
        database.get_type_by_id(self.type_id)
    }
}

/// Represents the physical properties of a structure.
#[derive(Clone, Debug, Default)]
pub struct Struct {
    /// A map of field name to field type.
    pub fields: HashMap<String, Field>,

    /// Cached size
    pub size: u32,
}

impl Struct {
    /// Create a new structure referencing the given database.
    ///
    /// # Arguments
    ///
    /// * `database` - The database in which the fields are contained.
    /// * `fields` - The fields for the structure.
    pub fn create(database: &TypeDatabase, fields: &[(&str, Field)]) -> Result<Self> {
        let mut new_fields = HashMap::with_capacity(fields.len());
        let mut bits = 0;
        for (name, field) in fields {
            let field_type = database
                .get_type_by_id(field.type_id)
                .ok_or(Error::InvalidTypeId)?;
            let reach = field.offset + field_type.get_size() * 8;
            if reach > bits {
                bits = reach
            }
            new_fields.insert(name.to_string(), *field);
        }

        Ok(Self {
            fields: new_fields,
            size: bits / 8,
        })
    }

    /// Returns the size of the structure in bytes.
    pub fn get_size(&self) -> u32 {
        self.size
    }
}

/// Represents the physical properties of an enum type.
#[derive(Clone, Debug, Default)]
pub struct Enum {
    /// The number of bits representing each value.
    pub bits: u32,

    /// An array holding a type of (name, value) for each enum value.
    pub values: Vec<(String, i64)>,
}

impl Enum {
    /// Returns the size of the enum values in bytes.
    pub fn get_size(&self) -> u32 {
        self.bits / 8
    }
}

/// Represents the physical properties of a function.
#[derive(Clone, Debug, Default)]
pub struct Function {
    /// The function parameters as an array of types.
    pub param_type_ids: Vec<usize>,
}

impl Function {
    /// Creates a function with the given type ids as parameters.
    ///
    /// # Arguments
    ///
    /// * `param_type_ids` - The type ids of the parameters.
    pub fn create(param_type_ids: &[usize]) -> Self {
        Self {
            param_type_ids: param_type_ids.to_vec(),
        }
    }
}

/// Variant for holding any kind of type.
#[derive(Clone, Debug, Default)]
pub enum BaseType {
    #[default]
    Void,
    Integer(Integer),
    Float(Float),
    Array(Array),
    Struct(Struct),
    Enum(Enum),
    Function(Function),
}

impl BaseType {
    /// Returns the number of bytes that the underlying type occupies. Types like
    /// void, functions, and, in the future, opaque types return 0.
    pub fn get_size(&self) -> u32 {
        match self {
            BaseType::Void => 0,
            BaseType::Integer(t) => t.get_size(),
            BaseType::Float(t) => t.get_size(),
            BaseType::Array(t) => t.get_size(),
            BaseType::Struct(t) => t.get_size(),
            BaseType::Enum(t) => t.get_size(),
            BaseType::Function(_) => 0,
        }
    }
}

/// Represents a fully-qualified type.
#[derive(Clone, Debug, Default)]
pub struct Type {
    /// The concrete base type.
    pub base_type: BaseType,

    /// Number of references.
    pub num_refs: u32,
}

impl Type {
    /// Convenience function for determining whether this is a pointer
    /// type or not (num_refs > 0). Makes code more clear.
    pub fn is_pointer(&self) -> bool {
        self.num_refs > 0
    }

    /// Gets the size, in bytes, of the underlying type. Returns 8, if
    /// the type is a pointer; BPF uses a 64-bit instruction set, on 32-bit
    /// systems, addresses will have the MSBs truncated.
    pub fn get_size(&self) -> u32 {
        if self.num_refs > 0 {
            return 8;
        }

        self.base_type.get_size()
    }
}

impl From<BaseType> for Type {
    fn from(base_type: BaseType) -> Self {
        Self {
            base_type,
            num_refs: 0,
        }
    }
}

/// Holds type information.
#[derive(Clone, Debug, Default)]
pub struct TypeDatabase {
    /// Map of name to type.
    types: Vec<Type>,
    name_map: HashMap<String, usize>,
}

impl TypeDatabase {
    /// Adds a type to the type database.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    /// * `ty` - The type to add.
    pub fn add_type(&mut self, name: Option<&str>, ty: &Type) -> Result<usize> {
        if let Some(name) = name {
            if let Some(index) = self.name_map.get(name) {
                self.types[*index] = ty.clone();
                Ok(*index)
            } else {
                let index = self.types.len();
                self.types.push(ty.clone());
                self.name_map.insert(name.to_string(), index);
                Ok(index)
            }
        } else {
            self.types.push(ty.clone());
            Ok(self.types.len() - 1)
        }
    }

    /// Finds a type in the database by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    pub fn get_type_by_name(&self, name: &str) -> Option<&Type> {
        let index = self.name_map.get(name)?;
        self.types.get(*index)
    }

    /// Finds a type in the database by id.
    ///
    /// # Arguments
    ///
    /// * `id` - The id of the type.
    pub fn get_type_by_id(&self, id: usize) -> Option<&Type> {
        self.types.get(id)
    }

    /// Gets a type's id by its name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    pub fn get_type_id_by_name(&self, name: &str) -> Option<usize> {
        Some(*self.name_map.get(name)?)
    }

    /// Convenience function for adding an integer type to the database.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    /// * `bytes` - The number of bits
    /// * `is_signed` - If the integer is signed.
    pub fn add_integer(
        &mut self,
        name: Option<&str>,
        bytes: u32,
        is_signed: bool,
    ) -> Result<usize> {
        let bits = bytes * 8;
        let new_integer = Integer {
            used_bits: bits,
            bits,
            is_signed,
        };

        self.add_type(name, &BaseType::Integer(new_integer).into())
    }

    /// Convenience function for adding a float type to the database.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    /// * `bits` - The number of bits.
    pub fn add_float(&mut self, name: Option<&str>, bits: u32) -> Result<usize> {
        let new_float = Float { bits };

        self.add_type(name, &BaseType::Float(new_float).into())
    }

    /// Convenience function for adding an array to the database.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    /// * `element_type_id` - The type id of the element.
    /// * `num_elements` - The number of elements in the array.
    pub fn add_array(
        &mut self,
        name: Option<&str>,
        element_type_id: usize,
        num_elements: u32,
    ) -> Result<usize> {
        let new_array = Array::create(self, element_type_id, num_elements)?;
        self.add_type(name, &BaseType::Array(new_array).into())
    }

    /// Convenience function for adding a struct to the database.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    /// * `fields` - The fields to add.
    pub fn add_struct(&mut self, name: Option<&str>, fields: &[(&str, Field)]) -> Result<usize> {
        let new_struct = Struct::create(self, fields)?;
        self.add_type(name, &BaseType::Struct(new_struct).into())
    }

    /// Convenience function for adding a struct to the database using
    /// a slice of (field_name, type_id). Types are added in order, and
    /// packed together contiguously.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    /// * `fields` - The fields to add (by id).
    pub fn add_struct_by_ids(
        &mut self,
        name: Option<&str>,
        fields: &[(&str, usize)],
    ) -> Result<usize> {
        let mut new_fields = Vec::with_capacity(fields.len());
        let mut offset = 0;
        for (field_name, type_id) in fields {
            let field_type = self
                .get_type_by_id(*type_id)
                .ok_or(Error::InvalidTypeName)?;
            let field = Field {
                offset,
                type_id: *type_id,
            };
            offset += field_type.get_size() * 8;
            new_fields.push((*field_name, field));
        }
        let new_struct = Struct::create(self, new_fields.as_slice())?;
        self.add_type(name, &BaseType::Struct(new_struct).into())
    }

    /// Convenience function for adding a struct to the database using
    /// a slice of (field_name, type_name). Types are added in order, and
    /// packed together contiguously.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the type.
    /// * `fields` - The fields to add (by name).
    pub fn add_struct_by_names(
        &mut self,
        name: Option<&str>,
        fields: &[(&str, &str)],
    ) -> Result<usize> {
        let mut new_fields = Vec::with_capacity(fields.len());
        let mut offset = 0;
        for (field_name, type_name) in fields {
            let field_type = self
                .get_type_by_name(type_name)
                .ok_or(Error::InvalidTypeName)?;
            let type_id = self
                .get_type_id_by_name(type_name)
                .ok_or(Error::InvalidTypeName)?;
            let field = Field { offset, type_id };
            offset += field_type.get_size() * 8;
            new_fields.push((*field_name, field));
        }
        let new_struct = Struct::create(self, new_fields.as_slice())?;
        self.add_type(name, &BaseType::Struct(new_struct).into())
    }
}

pub trait AddToTypeDatabase {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize>;
}

impl AddToTypeDatabase for u8 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("u8"), 1, false)
    }
}

impl AddToTypeDatabase for u16 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("u16"), 2, false)
    }
}

impl AddToTypeDatabase for u32 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("u32"), 4, false)
    }
}

impl AddToTypeDatabase for u64 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("u64"), 8, false)
    }
}

impl AddToTypeDatabase for i8 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("i8"), 1, true)
    }
}

impl AddToTypeDatabase for i16 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("i16"), 2, true)
    }
}

impl AddToTypeDatabase for i32 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("i32"), 4, true)
    }
}

impl AddToTypeDatabase for i64 {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        database.add_integer(Some("i64"), 8, true)
    }
}

impl<T: AddToTypeDatabase, const N: usize> AddToTypeDatabase for [T; N] {
    fn add_to_database(database: &mut TypeDatabase) -> Result<usize> {
        let type_id = T::add_to_database(database)?;
        database.add_array(
            Some(std::any::type_name::<[T; N]>()),
            type_id,
            N.try_into()?,
        )
    }
}
