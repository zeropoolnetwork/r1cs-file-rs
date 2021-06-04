use std::iter::FromIterator;

use nom::bytes::complete::{tag, take};
use nom::multi::{count, fill};
use nom::{number::complete::*, Err as NomErr, IResult};
use std::collections::HashMap;

const MAGIC: &[u8; 4] = b"r1cs";

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

    pub fn serialize() -> Vec<u8> {
        todo!()
    }

    fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, _magic) = tag(MAGIC)(i)?;
        let (i, _version) = tag(1u32.to_le_bytes())(i)?;

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
}

struct SectionHeader {
    _ty: SectionType,
    _size: u64,
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

        Ok((
            i,
            SectionHeader {
                _ty: ty,
                _size: size,
            },
        ))
    }
}

#[derive(PartialEq, Eq)]
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

pub struct Constraint {
    pub a: HashMap<u32, FieldElement>,
    pub b: HashMap<u32, FieldElement>,
    pub c: HashMap<u32, FieldElement>,
}

impl Constraint {
    fn parse(i: &[u8], fs: usize) -> IResult<&[u8], Self> {
        let (i, a) = Self::parse_combination(i, fs)?;
        let (i, b) = Self::parse_combination(i, fs)?;
        let (i, c) = Self::parse_combination(i, fs)?;

        Ok((i, Constraint { a, b, c }))
    }

    fn parse_combination(i: &[u8], fs: usize) -> IResult<&[u8], HashMap<u32, FieldElement>> {
        let (i, n) = le_u32(i)?;
        let mut map = HashMap::with_capacity(n as usize);

        let mut i = i;
        for _ in 0..n {
            let (input, index) = le_u32(i)?;
            let (input, factor) = FieldElement::parse(input, fs)?;
            map.insert(index, factor);

            i = input;
        }

        Ok((i, map))
    }
}

pub struct FieldElement(Vec<u8>);

impl FieldElement {
    fn parse(i: &[u8], size: usize) -> IResult<&[u8], Self> {
        let mut buf = vec![0; size];
        let (i, _) = fill(u8, &mut buf)(i)?;

        Ok((i, FieldElement(buf)))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl FromIterator<u8> for FieldElement {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        FieldElement(iter.into_iter().collect())
    }
}
