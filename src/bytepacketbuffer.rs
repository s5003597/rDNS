use std::io::ErrorKind::InvalidInput;
use std::io::Error;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    // Gives a new buffer for holding a packet
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    // Handling and manipulating buffer possition
    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<(), ()> {
        self.pos += steps;

        Ok(())
    }

    pub fn seek(&mut self, pos: usize) -> Result<(), ()> {
        self.pos = pos;

        Ok(())
    }

    // Reads single byte and progresses by one step
    pub fn read(&mut self) -> Result<(u8), (Error)> {
        if self.pos >= 512 {
            return Err(Error::new(InvalidInput, "End of buffer"))
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    // Gets data without changing self position
    pub fn get(&mut self, pos: usize) -> Result<(u8), (Error)> {
        if pos >= 512 {
            return Err(Error::new(InvalidInput, "End of buffer"))
        }
        Ok(self.buf[pos])
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<(&[u8]), (Error)> {
        if start + len >= 512 {
            return Err(Error::new(InvalidInput, "End of buffer"))
        }
        Ok(&self.buf[start..start+len as usize])
    }

    // Reads u16/u32 from buffer, stepping forward 2/4 bytes
    pub fn read_u16(&mut self) -> Result<(u16), (Error)> {
        Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    pub fn read_u32(&mut self) -> Result<(u32), (Error)> {
        Ok(
            ((self.read()? as u32) << 24) |
            ((self.read()? as u32) << 16) |
            ((self.read()? as u32) << 8) |
            ((self.read()? as u32) << 0))
    }

    // Reads domain names (with jump function)
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(), (Error)> {
        // Tracking position locally, so when can make jumps
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delim = "";
        loop {
            let len = self.get(pos)?;

            // If 2 MSB are set, indicates a jump
            if (len & 0xC0) == 0xC0 {
                // Set buffer position past label position
                if !jumped {
                    let _ = self.seek(pos+2);
                }

                // Read, calculate offset and jump
                let b2 = self.get(pos+1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // We now have position of label and jumped
                jumped = true;
            } else {
                // move byte forward, past the length byte
                pos += 1;

                // Domain names are terminated when label length is 0
                if len == 0 {
                    break;
                }

                // Appends delimiter to the output buffer first
                outstr.push_str(delim);
                // Decode ASCII bytes from label and append to buffer
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer)
                    .to_lowercase());

                // Changes delim; based on the way packets are decoded
                delim = ".";
                // set position above the full length of the label
                pos += len as usize;
            }
        }

        // If jumped already been performed, do not do it again
        if !jumped {
            let _ = self.seek(pos);
        }
        Ok(())
    }

    pub fn write(&mut self, val: u8) -> Result<(), (Error)> {
        if self.pos >= 512 {
            return Err(Error::new(InvalidInput, "End of buffer"))
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<(), (Error)> {
        self.write(val)?;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<(), (Error)> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;
        
        Ok(())
    }
    
    pub fn write_u32(&mut self, val: u32) -> Result<(), (Error)> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<(), (Error)> {
        let split_str = qname.split(".").collect::<Vec<&str>>();

        for label in split_str {
            let len = label.len();
            if len > 0x34 {
                return Err(Error::new(InvalidInput, "Single label exceeds the 63 character length"))
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }
        self.write_u8(0)?;
        Ok(())
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<(), ()> {
        self.buf[pos] = val;
        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), ()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}