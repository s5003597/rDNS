# RDNS - R Because It's Wirrten In Rust #
This repository was following the tutorial: https://github.com/EmilHernvall/dnsguide to get a deeper understanding of DNS server.

The different Structs allow us to serialise and deserialise DNS Packets, and their sections
(header, answers, records, type, etc). The segregation allows for better maintaining. However this project is still very new and there are a lot of improvements for me to make and get an even deeper understanding. The main.rs file is where the server is located and an infinite loop to accept handle questions.

# How DNS Works - TLDR
A DNS packet is made of 512 bytes, and usually uses the UDP protocol. 

The header is 12 bytes long, the last 8 bytes of the header content the lengths of each section. The first two bytes are the ID, the two bytes after that need to be converted into binary so the bits can represent different boolean values (QR, OPCODE, AC, TC, RD).

After the header, the question is present, which consist of query name, type and class.  The limited size of 512 bytes also means DNS use a jumping method to avoid sending same domain repeatedly.

there are two types of DNS servers, authoritative and caching. There are 13 root servers that handle the queries, they will direct a dns request to other servers and this will recursively repeat until a server knows the answer to a question.

TO DO:
 - Fix the bug of it not working with some domains, e.g. (facebook.com) which goes into a loop repeated loop
 - Refine code, look for improvements to put in place for a faster and more efficient rDNS
 - ADD DNSSEC!

Possible stuff to do?:
 - Concurrency
 - TCP for eDNS