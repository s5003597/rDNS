extern crate rand;
use super::{
    BytePacketBuffer,
    DnsRecord,
    DnsQuestion,
    DnsHeader,
    QueryType,
    };

use std::io::Error;
use rand::random;



#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<(DnsPacket), (Error)> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), (Error)> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &mut self.questions {
            question.write(buffer)?;
        }

        for rec in &mut self.answers {
            rec.write(buffer)?;
        }

        for rec in &mut self.authorities {
            rec.write(buffer)?;
        }

        for rec in &mut self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    // Picks a list of random A records from packet
    // Doesnt matter which one as they will all lead
    // to the same place, however might want to find
    // a way to find the lowest latency
    pub fn get_random_a(&self) -> Option<String> {
        if !self.answers.is_empty() {
            let idx = random::<usize>() % self.answers.len();
            let a_record = &self.answers[idx];
            if let DnsRecord::A { ref addr, .. } = *a_record {
                return Some(addr.to_string()); }}
        None
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS { ref domain, ref host, .. } = *auth {
                if !qname.ends_with(domain) {
                    continue; }

                // Scan NS Record for matching
                for rsrc in &self.resources {
                    if let DnsRecord::A { ref domain, ref addr, ttl } = *rsrc {
                        if domain != host {
                            continue; }

                        let rec = DnsRecord::A {
                            domain: host.clone(),
                            addr: *addr,
                            ttl: ttl };
                        new_authorities.push(rec);
                    }
                }
            }
        }
        // Picks the first match
        if !new_authorities.is_empty() {
            if let DnsRecord::A { addr, .. } = new_authorities[0] {
                return Some(addr.to_string()); }}
        None
    }

    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS { ref domain, ref host, .. } = *auth {
                if !qname.ends_with(domain) {
                    continue; }

                new_authorities.push(host); }}

        if !new_authorities.is_empty() {
            let idx = random::<usize>() % new_authorities.len();
            return Some(new_authorities[idx].clone()); }

        None
    }
}