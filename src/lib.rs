//! R1CS binary format parser/serializer
//!
//! Format specification: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md

use std::collections::BTreeMap;
use std::io::Write;
use std::iter::FromIterator;

use byteorder::{LittleEndian, WriteBytesExt};
use nom::bytes::complete::{tag, take};
use nom::multi::{count, fill};
use nom::{number::complete::*, Err as NomErr, IResult};
use std::ops::Deref;

const MAGIC: &[u8; 4] = b"r1cs";
const VERSION: &[u8; 4] = &[1, 0, 0, 0];

pub type Error<'a> = NomErr<nom::error::Error<&'a [u8]>>;

pub struct R1csFile {
    pub header: Header,
    pub constraints: Constraints,
    pub map: WireMap,
}

impl R1csFile {
    pub fn parse_bytes(input: &[u8]) -> Result<Self, Error> {
        match Self::parse(input) {
            IResult::Ok((_, res)) => Ok(res),
            IResult::Err(err) => Err(err),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new(); // TODO: Preallocate

        let _ = buf.write_all(MAGIC);
        let _ = buf.write_all(VERSION);

        self.header.serialize(&mut buf);
        self.constraints.serialize(&mut buf);
        self.map.serialize(&mut buf);

        buf
    }

    fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, _magic) = tag(MAGIC)(i)?;
        let (i, _version) = tag(VERSION)(i)?;

        // TODO: Should we support multiple sections of the same type?
        let (i, _num_sections) = le_u32(i)?;

        let (i, header) = Header::parse(i)?;
        let (i, constraints) =
            Constraints::parse(i, header.n_constraints as usize, header.field_size as usize)?;
        let (i, map) = WireMap::parse(i, header.n_labels as usize)?;

        Ok((
            i,
            R1csFile {
                header,
                constraints,
                map,
            },
        ))
    }
}

pub struct Header {
    pub field_size: u32,
    pub prime: FieldElement,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_prvt_in: u32,
    pub n_labels: u32,
    pub n_constraints: u32,
}

impl Header {
    fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, _section) = SectionHeader::parse(i)?;

        let (i, field_size) = le_u32(i)?;
        let (i, prime) = FieldElement::parse(i, field_size as usize)?;
        let (i, n_wires) = le_u32(i)?;
        let (i, n_pub_out) = le_u32(i)?;
        let (i, n_prvt_in) = le_u32(i)?;
        let (i, n_labels) = le_u32(i)?;
        let (i, n_constraints) = le_u32(i)?;

        Ok((
            i,
            Header {
                field_size,
                prime,
                n_wires,
                n_pub_out,
                n_prvt_in,
                n_labels,
                n_constraints,
            },
        ))
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        let header = SectionHeader {
            ty: SectionType::Header,
            size: 6 * 4 + self.field_size as u64,
        };

        header.serialize(buf);

        let _ = buf.write_u32::<LittleEndian>(self.field_size);
        self.prime.serialize(buf);
        let _ = buf.write_u32::<LittleEndian>(self.n_wires);
        let _ = buf.write_u32::<LittleEndian>(self.n_pub_out);
        let _ = buf.write_u32::<LittleEndian>(self.n_prvt_in);
        let _ = buf.write_u32::<LittleEndian>(self.n_labels);
        let _ = buf.write_u32::<LittleEndian>(self.n_constraints);
    }
}

pub struct Constraints {
    pub constraints: Vec<Constraint>,
}

impl Constraints {
    fn parse(i: &[u8], n_constraints: usize, fs: usize) -> IResult<&[u8], Self> {
        let (i, _section) = SectionHeader::parse(i)?;
        let mut constraints = Vec::with_capacity(std::mem::size_of::<Constraint>() * n_constraints);

        let mut i = i;
        for _ in 0..n_constraints {
            let (input, c) = Constraint::parse(i, fs)?;
            constraints.push(c);
            i = input;
        }

        Ok((i, Constraints { constraints }))
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        let header = SectionHeader {
            ty: SectionType::Constraint,
            size: self.constraints.iter().map(|c| c.size()).sum::<usize>() as u64,
        };

        header.serialize(buf);

        for c in &self.constraints {
            c.serialize(buf);
        }
    }
}

pub struct Constraint {
    pub combinations: [BTreeMap<u32, FieldElement>; 3],
}

impl Constraint {
    fn parse(i: &[u8], fs: usize) -> IResult<&[u8], Self> {
        let (i, a) = Self::parse_combination(i, fs)?;
        let (i, b) = Self::parse_combination(i, fs)?;
        let (i, c) = Self::parse_combination(i, fs)?;

        Ok((
            i,
            Constraint {
                combinations: [a, b, c],
            },
        ))
    }

    fn parse_combination(i: &[u8], fs: usize) -> IResult<&[u8], BTreeMap<u32, FieldElement>> {
        let (i, n) = le_u32(i)?;
        let mut map = BTreeMap::new();

        let mut i = i;
        for _ in 0..n {
            let (input, index) = le_u32(i)?;
            let (input, factor) = FieldElement::parse(input, fs)?;
            map.insert(index, factor);

            i = input;
        }

        Ok((i, map))
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        for comb in &self.combinations {
            let _ = buf.write_u32::<LittleEndian>(comb.len() as u32);

            for (index, factor) in comb.iter() {
                let _ = buf.write_u32::<LittleEndian>(*index);
                factor.serialize(buf);
            }
        }
    }

    fn size(&self) -> usize {
        let combs: usize = self
            .combinations
            .iter()
            .map(|c| c.values().map(|f| f.as_slice().len()).sum::<usize>() + c.len() * 4)
            .sum();

        combs + self.combinations.len() * 4
    }
}

pub struct WireMap {
    pub label_ids: Vec<u64>,
}

impl WireMap {
    fn parse(i: &[u8], num: usize) -> IResult<&[u8], Self> {
        let (i, _section) = SectionHeader::parse(i)?;
        let (i, label_ids) = count(le_u64, num)(i)?;

        Ok((i, WireMap { label_ids }))
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        for label_id in &self.label_ids {
            let _ = buf.write_u64::<LittleEndian>(*label_id);
        }
    }
}

struct SectionHeader {
    ty: SectionType,
    size: u64,
}

impl SectionHeader {
    fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, ty) = SectionType::parse(i)?;
        let (i, size) = le_u64(i)?;

        // Ignore invalid sections
        if ty == SectionType::Unknown {
            let (i, _) = take(size)(i)?;
            return Self::parse(i); // TODO: Get rid of recursion
        }

        Ok((i, SectionHeader { ty, size }))
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        let _ = buf.write_u32::<LittleEndian>(self.ty as u32);
        let _ = buf.write_u64::<LittleEndian>(self.size);
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
enum SectionType {
    Header = 0,
    Constraint = 1,
    Wire2LabelIdMap = 2,
    Unknown = u32::MAX,
}

impl SectionType {
    fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, num) = le_u32(i)?;

        let ty = match num {
            0 => SectionType::Header,
            1 => SectionType::Constraint,
            2 => SectionType::Wire2LabelIdMap,
            _ => SectionType::Unknown,
        };

        Ok((i, ty))
    }
}

pub struct FieldElement(Vec<u8>);

impl FieldElement {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn parse(i: &[u8], size: usize) -> IResult<&[u8], Self> {
        let mut buf = vec![0; size];
        let (i, _) = fill(u8, &mut buf)(i)?;

        Ok((i, FieldElement(buf)))
    }

    fn serialize(&self, buf: &mut Vec<u8>) {
        let _ = buf.write_all(&self.0);
    }
}

impl FromIterator<u8> for FieldElement {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        FieldElement(iter.into_iter().collect())
    }
}

impl Deref for FieldElement {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let data = std::fs::read("test_circuit.r1cs").unwrap();
        let file = R1csFile::parse_bytes(&data).unwrap();

        assert!(true);
    }
}
