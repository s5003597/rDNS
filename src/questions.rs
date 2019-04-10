use super::BytePacketBuffer;
use super::QueryType;
use std::io::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), (Error)> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), (Error)> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}