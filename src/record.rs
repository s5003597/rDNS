use super::BytePacketBuffer;
use super::QueryType;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::io::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN { // 0
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A { // 1
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    // NS 2
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    // CNAME 5
    CNAME {
        domain: String,
        host: String,
        ttl: u32
    },
    // MX 15
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    // AAAA 28
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<(DnsRecord), (Error)> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?; // Class, which is ignored
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        // Handles each type seperately
        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8);
                
                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl
                })
            },
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 =  buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16);
                
                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl
                })
            },
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain: domain,
                    host: ns,
                    ttl: ttl
                })
            },
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: ttl
                })
            },
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain: domain,
                    priority: priority,
                    host: mx,
                    ttl: ttl,
                })
            },
            QueryType::UNKNOWN(_) => {
                let _ = buffer.step(data_len as usize);

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl: ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(usize), (Error)> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A { ref domain, ref addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            },
            DnsRecord::NS { ref domain, ref host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                let _ = buffer.set_u16(pos, size as u16);
            },
            DnsRecord::CNAME { ref domain, ref host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                let _ = buffer.set_u16(pos, size as u16);
            },
            DnsRecord::MX { ref domain, priority, ref host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                let _ = buffer.set_u16(pos, size as u16);
            },
            DnsRecord::AAAA { ref domain, ref addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            },
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping Record: {:?}", self);
            }
        }
        Ok(buffer.pos() - start_pos)
    }
}