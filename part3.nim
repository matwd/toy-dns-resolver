import std/strformat
import std/cmdline
import std/endians
import std/random
import std/net
import part1
import part2

const
    TYPE_A = 1
    TYPE_AAAA = 28
    CLASS_IN = 1
    TYPE_NS = 2

proc `$`(record: DNSRecord): string =
    let name = cast[string](record.name)
    var class: string = $record.class
    if record.class == CLASS_IN:
        class = "CLASS_IN"

    var `type`: string
    case record.type
    of TYPE_A: 
        `type` = "TYPE_A"
    of TYPE_AAAA: 
        `type` = "TYPE_AAAA"
    of TYPE_NS:
        `type` = "TYPE_NS"
    else:
        `type` = $record.type

    var data: string
    case record.type
    of TYPE_A: 
        data = record.data.ipv4_to_string
    of TYPE_AAAA: 
        data = record.data.ipv6_to_string
    of TYPE_NS:
        data = cast[string](record.data)
    else:
        data = $record.data

    return fmt"DNSRecord(name: {name}, type: {`type`}, class: {class}, ttl: {record.ttl}, data: {data})"

proc build_query(domain_name: string, record_type: uint16): seq[byte] =
    let 
        name = encode_dns_name(domain_name)
        id: uint16 = uint16(rand(65535))
        header = DNSHeader(id: id, num_questions: 1, flags: 0)
        question = DNSQuestion(name: name, `type`: record_type, class: CLASS_IN)
    return header.to_bytes & question.to_bytes


proc parse_record*(dns_packet: seq[byte], offset: var int64): DNSRecord =
    var
        name = decode_name(dns_packet, offset)
        data_len: uint16
        record = DNSRecord(name: name)
    bigEndian16(addr record.`type`,   addr dns_packet[offset])
    bigEndian16(addr record.class,    addr dns_packet[offset+2])
    bigEndian32(addr record.ttl,      addr dns_packet[offset+4])
    bigEndian16(addr data_len, addr dns_packet[offset+8])
    offset += 10
    if record.type == TYPE_NS:
        record.data = decode_name(dns_packet, offset)
    elif record.type == TYPE_A:
        record.data = dns_packet[offset..offset+int64(data_len)-1]
        offset += int64(data_len)
        # in contrast to original tutorial i am going to dont cast
        # to ip address string, because its no that useful in nim
        # record.data = cast[seq[byte]](record.data.ip_to_string)
    else:
        record.data = dns_packet[offset..offset+int64(data_len)-1]
        offset += int64(data_len)
    return record

proc parse_dns_packet*(data: seq[byte]): DNSPacket =
    var
        offset: int64 = 0
        header = parse_header(data, offset)
        packet = DNSPacket()

    for i in 1..int64(header.num_questions):
      packet.questions.add(parse_question(data, offset))

    for i in 1..int64(header.num_answers):
      packet.answers.add(parse_record(data, offset))

    for i in 1..int64(header.num_authorities):
      packet.authorities.add(parse_record(data, offset))

    for i in 1..int64(header.num_additionals):
      packet.additionals.add(parse_record(data, offset))

    return packet


proc send_query(ip_address: string, domain_name: string, record_type: uint16): DNSPacket =
    var response: string
    var ip_address = ip_address
    let query = build_query(domain_name, record_type)
    let socket = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)

    var port = Port(53)

    socket.sendTo(ip_address, port, addr query[0], len(query))
    let _ = socket.recvFrom(response, 1024, ip_address, port)

    return parse_dns_packet(cast[seq[byte]](response))

proc get_answer(packet: DNSPacket): seq[byte] =
    # return the first A record in the Answer section
    for x in packet.answers:
        if x.`type` == TYPE_A:
            return x.data
    return @[]
        
proc get_nameserver_ip(packet: DNSPacket): seq[byte] =
    # return the first A record in the Additional section
    for x in packet.additionals:
        if x.`type` == TYPE_A:
            return x.data
    return @[]

proc get_nameserver(packet: DNSPacket): string =
    # return the first NS record in the Authority section
    for x in packet.authorities:
        if x.`type` == TYPE_NS:
            return cast[string](x.data)
    return ""

proc resolve(domain_name: string, record_type: uint16): seq[byte] =
    var nameserver: string = "198.41.0.4"
    while true:
        echo(fmt"Querying {nameserver} for {domain_name}")
        var response = send_query(nameserver, domain_name, record_type)
        var ip = get_answer(response)
        if ip != @[]:
            return ip

        var nsIP = get_nameserver_ip(response).ipv4_to_string
        if nsIP != "":
            nameserver = nsIP
            continue

        var nsDomain = get_nameserver(response)
        if nsDomain != "":
            nameserver = resolve(nsDomain, TYPE_A).ipv4_to_string
        else:
            raise newException(Defect, "Failed to resolve domain name")

if paramCount() == 1:
    echo resolve(paramStr(1), TYPE_A).ipv4_to_string
else:
    echo fmt"usage: {paramStr(0)} [domain]"

