// Conventionall DNS uses UDP transport, however there are exceptions
// UDP packets are limited to 512 bytes in size
mod bytepacketbuffer;
mod header;
mod dns_packet;
mod qtype;
mod questions;
mod record;
mod opcodes;

use bytepacketbuffer::BytePacketBuffer;
use header::DnsHeader;
use questions::DnsQuestion;
use record::DnsRecord;
use opcodes::ResultCode;
use dns_packet::DnsPacket;
use qtype::QueryType;

use std::io::Error;

//use std::fs::File;
//use std::io::Read;
use std::net::UdpSocket;

fn lookup(qname: &str, qtype: QueryType, server: (&str, u16)) -> Result<(DnsPacket), (Error)> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    DnsPacket::from_buffer(&mut res_buffer)
}

#[allow(dead_code)]
fn read_test(packet: DnsPacket) {
    /*let mut f = File::open("response_packet.txt").unwrap();
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf).unwrap();

    let packet = DnsPacket::from_buffer(&mut buffer).unwrap();*/
    println!("{:?}", packet.header);

    for q in packet.questions {
        println!("{:?}", q);
    }

    for rec in packet.answers {
        println!("{:?}", rec);
    }

    for rec in packet.authorities {
        println!("{:?}", rec);
    }

    for rec in packet.resources {
        println!("{:?}", rec);
    }
}

fn test_2() {
    // perform A query for google
    let qname = "yahoo.com";
    let qtype = QueryType::MX;

    // Uses cloudflare's dns server
    let server = ("1.1.1.1", 53);

    // Binds socket to port
    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();

    // Build a DNS Packet
    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    // Writes to the packet's buffer (512 bytes)
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    // Sends it to the server
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server).unwrap();

    // Prepare for receiving the response
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    // Parses buffer data
    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();
    read_test(res_packet);
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<(DnsPacket), (Error)> {
    // Starting with *a.root-servers.net*
    let mut ns = "198.41.0.4".to_string();

    loop {
        println!("Attempting Lookup of {:?} {} with ns {}", qtype, qname, ns);

        // The next step is to send a query
        let ns_copy = ns.clone();

        let server = (ns_copy.as_str(), 53);
        let response = lookup(qname, qtype.clone(), server)?;

        if !response.answers.is_empty() &&
            response.header.rescode == ResultCode::NOERROR {
                return Ok(response.clone()); }

        // NXDOMAIN (name doesnt exist)
        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response.clone()); }

        // Tries nameserver based NS & corrosponding A record
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns.clone();
            continue; }
        
        // If no NS, go with what the last server said
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response.clone()),
        };

        // Rabbit hole 101
        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A).unwrap();

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns.clone();
        } else {
            return Ok(response.clone())
        }
    }
}

fn main() {
    //let server = ("1.1.1.1", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();

    // Infinite loop to handle requests
    loop {
        let mut req_buffer = BytePacketBuffer::new();
        // Gets data from src
        let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to read from UDP socket: {:?}", e);
                continue;
            },
        };

        // Serialises data into DNS Packet
        let request = match DnsPacket::from_buffer(&mut req_buffer) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to serialise UDP Request: {:?}", e);
                continue;
            },
        };

        // Initialises response packet
        let mut packet = DnsPacket::new();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        // Checks is there are any questions (valid lookup)
        if request.questions.is_empty() {
            packet.header.rescode = ResultCode::FORMERR;
        } else {
            let question = &request.questions[0];
            println!("Received Query: {:?}", question);
            if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
                packet.questions.push(question.clone());
                packet.header.rescode = result.header.rescode;

                for rec in result.answers {
                    println!("Answer: {:?}", rec);
                    packet.answers.push(rec);
                }

                for rec in result.authorities {
                    println!("Authority: {:?}", rec);
                    packet.authorities.push(rec);
                }

                for rec in result.resources {
                    println!("Resource: {:?}", rec);
                    packet.resources.push(rec);
                }
            } else {
                packet.header.rescode = ResultCode::SERVFAIL;
            }

            // Encode response and respond
            let mut res_buffer = BytePacketBuffer::new();
            match packet.write(&mut res_buffer) {
                Ok(_) => {},
                Err(e) => {
                    println!("Failed to encode UDP packed: {:?}", e);
                    continue;
                }
            };

            let len = res_buffer.pos();
            let data = match res_buffer.get_range(0, len) {
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to get response buffer: {:?}", e);
                    continue;
                }
            };

            match socket.send_to(data, src) {
                Ok(_) => {},
                Err(e) => {
                    println!("Failed to send response: {:?}", e);
                    continue;
                }
            };
        }
    }
}