use crate::error::{Error, Result};
use crate::types::{Array, BaseType, Field, Float, Integer, Struct, Type, TypeDatabase};

use btf::{
    Array as BtfArray, Btf, Float as BtfFloat, Integer as BtfInteger, Struct as BtfStruct,
    Type as BtfType,
};

impl TypeDatabase {
    /// Adds a void type.
    ///
    /// # Arguments
    ///
    /// * `name` - The optional name of the type.
    /// * `num_refs` - The reference count on the type.
    fn add_btf_void(&mut self, name: Option<&str>, num_refs: u32) -> Result<usize> {
        let new_type = Type {
            base_type: BaseType::Void,
            num_refs,
        };

        self.add_type(name, &new_type)
    }

    /// Adds a BTF integer type.
    ///
    /// # Arguments
    ///
    /// * `name` - The optional name of the type.
    /// * `integer` - The BTF integer to add.
    /// * `num_refs` - The reference count on the type.
    fn add_btf_integer(
        &mut self,
        name: Option<&str>,
        integer: &BtfInteger,
        num_refs: u32,
    ) -> Result<usize> {
        let base_type = BaseType::Integer(Integer {
            used_bits: integer.used_bits,
            bits: integer.bits,
            is_signed: integer.is_signed,
        });

        let new_type = Type {
            base_type,
            num_refs,
        };

        self.add_type(name, &new_type)
    }

    /// Adds a BTF float type.
    ///
    /// # Arguments
    ///
    /// * `name` - The optional name of the type.
    /// * `float` - The BTF float to add.
    /// * `num_refs` - The reference count on the type.
    fn add_btf_float(
        &mut self,
        name: Option<&str>,
        float: &BtfFloat,
        num_refs: u32,
    ) -> Result<usize> {
        let base_type = BaseType::Float(Float { bits: float.bits });

        let new_type = Type {
            base_type,
            num_refs,
        };

        self.add_type(name, &new_type)
    }

    /// Adds a BTF array type.
    ///
    /// # Arguments
    ///
    /// * `name` - The optional name of the type.
    /// * `array` - The BTF array to add.
    /// * `num_refs` - The reference count on the type.
    fn add_btf_array(
        &mut self,
        name: Option<&str>,
        array: &BtfArray,
        num_refs: u32,
    ) -> Result<usize> {
        let btf_id_name = format!(".btf.{}", array.elem_type_id);
        let element_type_id = self
            .get_type_id_by_name(&btf_id_name)
            .ok_or(Error::NoConversion)?;
        let base_type = BaseType::Array(Array::create(self, element_type_id, array.num_elements)?);
        let new_type = Type {
            base_type,
            num_refs,
        };
        self.add_type(name, &new_type)
    }

    /// Adds a BTF struct type.
    ///
    /// # Arguments
    ///
    /// * `name` - The optional name of the type.
    /// * `structure` - The BTF struct to add.
    /// * `num_refs` - The reference count on the type.
    fn add_btf_struct(
        &mut self,
        name: Option<&str>,
        structure: &BtfStruct,
        num_refs: u32,
    ) -> Result<usize> {
        let mut fields = Vec::with_capacity(structure.members.len());
        for member in &structure.members {
            let btf_id_name = format!(".btf.{}", member.type_id);
            let type_id = self
                .get_type_id_by_name(&btf_id_name)
                .ok_or(Error::NoConversion)?;
            let field = Field {
                offset: member.offset,
                type_id,
            };
            fields.push((member.name.as_str(), field));
        }

        let base_type = BaseType::Struct(Struct::create(self, fields.as_slice())?);
        let new_type = Type {
            base_type,
            num_refs,
        };
        self.add_type(name, &new_type)
    }

    /// Adds a BTF type to the database.
    ///
    /// # Arguments
    ///
    /// * `name` - The optional name of the type.
    /// * `btf_type` - The BTF type.
    /// * `num_refs` - The reference count on the type.
    fn add_btf_type(
        &mut self,
        name: Option<&str>,
        btf_type: &BtfType,
        num_refs: u32,
    ) -> Result<usize> {
        match btf_type {
            BtfType::Integer(integer) => self.add_btf_integer(name, integer, num_refs),
            BtfType::Float(float) => self.add_btf_float(name, float, num_refs),
            BtfType::Array(array) => self.add_btf_array(name, array, num_refs),
            BtfType::Struct(structure) => self.add_btf_struct(name, structure, num_refs),
            _ => self.add_btf_void(name, num_refs),
        }
    }

    /// Adds a parsed list of BTF types to this type database.
    ///
    /// # Arguments
    ///
    /// * `name` - The optional name of the type.
    /// * `btf` - The BTF types.
    ///
    /// # Example
    /// ```
    /// use bpf_script::types::TypeDatabase;
    /// use btf::Btf;
    ///
    /// let btf = Btf::from_file("/sys/kernel/btf/vmlinux").expect("Failed to parse vmlinux btf");
    /// let mut database = TypeDatabase::default();
    ///
    /// database
    ///     .add_btf_types(&btf)
    ///     .expect("failed to add btf types");
    /// database
    ///     .get_type_by_name("task_struct")
    ///     .expect("Couldn't find task_struct");
    /// ```
    pub fn add_btf_types(&mut self, btf: &Btf) -> Result<()> {
        // Types can forward reference, add placeholder for each.
        for i in 0..btf.get_types().len() {
            let btf_id_name = format!(".btf.{}", i);
            self.add_btf_void(Some(&btf_id_name), 0)?;
        }

        for (i, btf_type) in btf.get_types().iter().enumerate() {
            let btf_id_name = format!(".btf.{}", i);
            self.add_btf_type(Some(&btf_id_name), &btf_type.base_type, btf_type.num_refs)?;

            for name in &btf_type.names {
                self.add_btf_type(Some(name), &btf_type.base_type, btf_type.num_refs)?;
            }
        }

        Ok(())
    }
}
