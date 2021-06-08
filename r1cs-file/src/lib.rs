//! R1CS binary format parser/serializer
//!
//! Format specification: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md

use std::io::{Error, ErrorKind, Read, Result, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

const MAGIC: &[u8; 4] = b"r1cs";
const VERSION: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub struct R1csFile<const FS: usize> {
    pub header: Header<FS>,
    pub constraints: Constraints<FS>,
    pub map: WireMap,
}

impl<const FS: usize> R1csFile<FS> {
    pub fn read<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != *MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid magic number"));
        }

        let version = r.read_u32::<LittleEndian>()?;
        if version != VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "Unsupported version"));
        }

        // TODO: Should we support multiple sections of the same type?
        let _num_sections = r.read_u32::<LittleEndian>()?;

        let header = Header::read(&mut r)?;
        let constraints = Constraints::read(&mut r, header.n_constraints as usize)?;
        let map = WireMap::read(&mut r)?;

        Ok(R1csFile {
            header,
            constraints,
            map,
        })
    }

    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(MAGIC)?;
        w.write_u32::<LittleEndian>(VERSION)?;
        w.write_u32::<LittleEndian>(3)?; // number of sections

        self.header.write(&mut w)?;
        self.constraints.write(&mut w)?;
        self.map.write(&mut w)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Header<const FS: usize> {
    pub prime: FieldElement<FS>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prvt_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
}

impl<const FS: usize> Header<FS> {
    fn read<R: Read>(mut r: R) -> Result<Self> {
        let _section = SectionHeader::read(&mut r)?;

        let field_size = r.read_u32::<LittleEndian>()?;
        if field_size != FS as u32 {
            return Err(Error::new(ErrorKind::InvalidData, "Wrong field size"));
        }

        let prime = FieldElement::read(&mut r)?;
        let n_wires = r.read_u32::<LittleEndian>()?;
        let n_pub_out = r.read_u32::<LittleEndian>()?;
        let n_pub_in = r.read_u32::<LittleEndian>()?;
        let n_prvt_in = r.read_u32::<LittleEndian>()?;
        let n_labels = r.read_u64::<LittleEndian>()?;
        let n_constraints = r.read_u32::<LittleEndian>()?;

        Ok(Header {
            prime,
            n_wires,
            n_pub_out,
            n_pub_in,
            n_prvt_in,
            n_labels,
            n_constraints,
        })
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        let header = SectionHeader {
            ty: SectionType::Header,
            size: 6 * 4 + 8 + FS as u64,
        };

        header.write(&mut w)?;

        w.write_u32::<LittleEndian>(FS as u32)?;
        self.prime.write(&mut w)?;
        w.write_u32::<LittleEndian>(self.n_wires)?;
        w.write_u32::<LittleEndian>(self.n_pub_out)?;
        w.write_u32::<LittleEndian>(self.n_pub_in)?;
        w.write_u32::<LittleEndian>(self.n_prvt_in)?;
        w.write_u64::<LittleEndian>(self.n_labels)?;
        w.write_u32::<LittleEndian>(self.n_constraints)?;

        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Constraints<const FS: usize>(pub Vec<Constraint<FS>>);

impl<const FS: usize> Constraints<FS> {
    fn read<R: Read>(mut r: R, n_constraints: usize) -> Result<Self> {
        let _section = SectionHeader::read(&mut r)?;
        let mut constraints =
            Vec::with_capacity(std::mem::size_of::<Constraint<FS>>() * n_constraints);

        for _ in 0..n_constraints {
            let c = Constraint::read(&mut r)?;
            constraints.push(c);
        }

        Ok(Constraints(constraints))
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        let header = SectionHeader {
            ty: SectionType::Constraint,
            size: self.0.iter().map(|c| c.size()).sum::<usize>() as u64,
        };

        header.write(&mut w)?;

        for c in &self.0 {
            c.write(&mut w)?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Constraint<const FS: usize>(
    pub Vec<(FieldElement<FS>, u32)>,
    pub Vec<(FieldElement<FS>, u32)>,
    pub Vec<(FieldElement<FS>, u32)>,
);

impl<const FS: usize> Constraint<FS> {
    fn read<R: Read>(mut r: R) -> Result<Self> {
        let a = Self::read_combination(&mut r)?;
        let b = Self::read_combination(&mut r)?;
        let c = Self::read_combination(&mut r)?;

        Ok(Constraint(a, b, c))
    }

    fn read_combination<R: Read>(mut r: R) -> Result<Vec<(FieldElement<FS>, u32)>> {
        let n = r.read_u32::<LittleEndian>()?;
        let mut factors = Vec::new();

        for _ in 0..n {
            let index = r.read_u32::<LittleEndian>()?;
            let factor = FieldElement::read(&mut r)?;
            factors.push((factor, index));
        }

        Ok(factors)
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        let mut write = |comb: &Vec<(FieldElement<FS>, u32)>| -> Result<()> {
            w.write_u32::<LittleEndian>(comb.len() as u32)?;

            for (factor, index) in comb {
                w.write_u32::<LittleEndian>(*index)?;
                factor.write(&mut w)?;
            }

            Ok(())
        };

        write(&self.0)?;
        write(&self.1)?;
        write(&self.2)?;

        Ok(())
    }

    fn size(&self) -> usize {
        let a = self.0.iter().map(|(f, _)| f.len()).sum::<usize>() + self.0.len() * 4;
        let b = self.1.iter().map(|(f, _)| f.len()).sum::<usize>() + self.1.len() * 4;
        let c = self.2.iter().map(|(f, _)| f.len()).sum::<usize>() + self.2.len() * 4;

        a + b + c + 3 * 4
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct WireMap(pub Vec<u64>);

impl WireMap {
    fn read<R: Read>(mut r: R) -> Result<Self> {
        let section = SectionHeader::read(&mut r)?;
        let num_labels = section.size / 8;
        let mut label_ids = Vec::with_capacity(num_labels as usize);

        for _ in 0..num_labels {
            label_ids.push(r.read_u64::<LittleEndian>()?);
        }

        Ok(WireMap(label_ids))
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        let header = SectionHeader {
            ty: SectionType::Wire2LabelIdMap,
            size: self.0.len() as u64 * 8,
        };

        header.write(&mut w)?;

        for label_id in &self.0 {
            w.write_u64::<LittleEndian>(*label_id)?;
        }

        Ok(())
    }
}

struct SectionHeader {
    ty: SectionType,
    size: u64,
}

impl SectionHeader {
    fn read<R: Read>(mut r: R) -> Result<Self> {
        let ty = SectionType::read(&mut r)?;
        let size = r.read_u64::<LittleEndian>()?;

        // Ignore invalid sections
        if ty == SectionType::Unknown {
            std::io::copy(&mut r.by_ref().take(size), &mut std::io::sink())?;
            return Self::read(r); // TODO: Get rid of recursion
        }

        Ok(SectionHeader { ty, size })
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_u32::<LittleEndian>(self.ty as u32)?;
        w.write_u64::<LittleEndian>(self.size)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
enum SectionType {
    Header = 1,
    Constraint = 2,
    Wire2LabelIdMap = 3,
    Unknown = u32::MAX,
}

impl SectionType {
    fn read<R: Read>(mut r: R) -> Result<Self> {
        let num = r.read_u32::<LittleEndian>()?;

        let ty = match num {
            1 => SectionType::Header,
            2 => SectionType::Constraint,
            3 => SectionType::Wire2LabelIdMap,
            _ => SectionType::Unknown,
        };

        Ok(ty)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FieldElement<const FS: usize>([u8; FS]);

impl<const FS: usize> FieldElement<FS> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    fn read<R: Read>(mut r: R) -> Result<Self> {
        let mut buf = [0; FS];
        r.read_exact(&mut buf)?;

        Ok(FieldElement(buf))
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&self.0[..])
    }
}

impl<const FS: usize> From<[u8; FS]> for FieldElement<FS> {
    fn from(array: [u8; FS]) -> Self {
        FieldElement(array)
    }
}

impl<const FS: usize> std::ops::Deref for FieldElement<FS> {
    type Target = [u8; FS];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_parse() {
        let data = std::fs::read("tests/simple_circuit.r1cs").unwrap();
        let file = R1csFile::<32>::read(data.as_slice()).unwrap();

        // Thanks to https://github.com/poma/zkutil/blob/5d789ab3757dcd79eff244ca4998d7ab91683b40/src/r1cs_reader.rs#L188
        assert_eq!(
            file.header.prime,
            FieldElement::from(hex!(
                "010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430"
            ))
        );
        assert_eq!(file.header.n_wires, 7);
        assert_eq!(file.header.n_pub_out, 1);
        assert_eq!(file.header.n_pub_in, 2);
        assert_eq!(file.header.n_prvt_in, 3);
        assert_eq!(file.header.n_labels, 0x03e8);
        assert_eq!(file.header.n_constraints, 3);

        assert_eq!(file.constraints.0.len(), 3);
        assert_eq!(file.constraints.0[0].0.len(), 2);
        assert_eq!(file.constraints.0[0].0[0].1, 5);
        assert_eq!(
            file.constraints.0[0].0[0].0,
            FieldElement::from(hex!(
                "0300000000000000000000000000000000000000000000000000000000000000"
            )),
        );
        assert_eq!(file.constraints.0[2].1[0].1, 0);
        assert_eq!(
            file.constraints.0[2].1[0].0,
            FieldElement::from(hex!(
                "0600000000000000000000000000000000000000000000000000000000000000"
            )),
        );
        assert_eq!(file.constraints.0[1].2.len(), 0);

        assert_eq!(file.map.0.len(), 7);
        assert_eq!(file.map.0[1], 3);
    }

    #[test]
    fn test_serialize() {
        let data = std::fs::read("tests/test_circuit.r1cs").unwrap();
        let parsed_file = R1csFile::<32>::read(data.as_slice()).unwrap();
        let mut serialized_file = Vec::new();
        parsed_file.write(&mut serialized_file).unwrap();

        // std::fs::write("simple_circuit_new.r1cs", &serialized_file).unwrap();

        assert_eq!(data.len(), serialized_file.len());
        assert_eq!(data, serialized_file);
    }
}
