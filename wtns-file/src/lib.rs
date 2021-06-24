//! Implementation of binary .wtns file parser/serializer.
//! According to https://github.com/iden3/snarkjs/blob/master/src/wtns_utils.js

use std::io::{Error, ErrorKind, Read, Result, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

const MAGIC: &[u8; 4] = b"wtns";

#[derive(Debug, PartialEq)]
pub struct WtnsFile<const FS: usize> {
    pub version: u32,
    pub header: Header<FS>,
    pub witness: Witness<FS>,
}

impl<const FS: usize> WtnsFile<FS> {
    pub fn from_vec(witness: Vec<FieldElement<FS>>, prime: FieldElement<FS>) -> Self {
        WtnsFile {
            version: 1,
            header: Header {
                field_size: FS as u32,
                prime,
                witness_len: witness.len() as u32,
            },
            witness: Witness(witness),
        }
    }

    pub fn read<R: Read>(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;

        if magic != *MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid magic number"));
        }

        let version = r.read_u32::<LittleEndian>()?;
        if version > 2 {
            return Err(Error::new(ErrorKind::InvalidData, "Unsupported version"));
        }

        let num_sections = r.read_u32::<LittleEndian>()?;
        if num_sections > 2 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Number of sections >2 is not supported",
            ));
        }

        let header = Header::read(&mut r)?;
        let witness = Witness::read(&mut r, &header)?;

        Ok(WtnsFile {
            version,
            header,
            witness,
        })
    }

    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(MAGIC)?;
        w.write_u32::<LittleEndian>(self.version)?;
        w.write_u32::<LittleEndian>(2)?;
        self.header.write(&mut w)?;
        self.witness.write(&mut w)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct Header<const FS: usize> {
    pub field_size: u32,
    pub prime: FieldElement<FS>,
    pub witness_len: u32,
}

impl<const FS: usize> Header<FS> {
    pub fn read<R: Read>(mut r: R) -> Result<Self> {
        let sec_type = SectionType::read(&mut r)?;
        if sec_type != SectionType::Header {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid section type: expected header",
            ));
        }

        let sec_size = r.read_u64::<LittleEndian>()?;
        if sec_size != 4 + FS as u64 + 4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid header section size",
            ));
        }

        let field_size = r.read_u32::<LittleEndian>()?;
        let prime = FieldElement::read(&mut r)?;

        if field_size != FS as u32 {
            return Err(Error::new(ErrorKind::InvalidData, "Wrong field size"));
        }

        let witness_len = r.read_u32::<LittleEndian>()?;

        Ok(Header {
            field_size,
            prime,
            witness_len,
        })
    }

    pub fn write<W: Write>(&self, mut w: W) -> Result<()> {
        SectionType::Header.write(&mut w)?;

        let sec_size = 4 + FS as u64 + 4;
        w.write_u64::<LittleEndian>(sec_size)?;

        w.write_u32::<LittleEndian>(FS as u32)?;
        self.prime.write(&mut w)?;
        w.write_u32::<LittleEndian>(self.witness_len)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct Witness<const FS: usize>(pub Vec<FieldElement<FS>>);

impl<const FS: usize> Witness<FS> {
    pub fn read<R: Read>(mut r: R, header: &Header<FS>) -> Result<Self> {
        let sec_type = SectionType::read(&mut r)?;
        if sec_type != SectionType::Witness {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid section type: expected witness"));
        }
        let sec_size = r.read_u64::<LittleEndian>()?;

        if sec_size != header.witness_len as u64 * FS as u64 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid witness section size",
            ));
        }

        let mut witness = Vec::with_capacity(header.witness_len as usize);
        for _ in 0..header.witness_len {
            witness.push(FieldElement::read(&mut r)?);
        }

        Ok(Witness(witness))
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        SectionType::Witness.write(&mut w)?;

        let sec_size = (self.0.len() * FS) as u64;
        w.write_u64::<LittleEndian>(sec_size)?;

        for e in &self.0 {
            e.write(&mut w)?;
        }

        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(u32)]
pub enum SectionType {
    Header = 1,
    Witness = 2,
    Unknown = u32::MAX,
}

impl SectionType {
    fn read<R: Read>(mut r: R) -> Result<Self> {
        let num = r.read_u32::<LittleEndian>()?;

        let ty = match num {
            1 => SectionType::Header,
            2 => SectionType::Witness,
            _ => SectionType::Unknown,
        };

        Ok(ty)
    }

    fn write<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_u32::<LittleEndian>(*self as u32)?;

        Ok(())
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
    use std::io::Cursor;

    const FS: usize = 32;

    fn fe() -> FieldElement<FS> {
        FieldElement::from([1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
    }

    #[test]
    fn test() {
        let file = WtnsFile::<FS>::from_vec(vec![fe(), fe(), fe()], fe());
        let mut data = Vec::new();
        file.write(&mut data).unwrap();

        let new_file = WtnsFile::read(Cursor::new(data)).unwrap();

        assert_eq!(file, new_file);
    }
}