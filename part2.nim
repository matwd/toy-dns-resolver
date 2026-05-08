import ./part1
import std/strutils
import std/endians

type DNSRecord* = object
    name*: seq[byte] 
    `type`*: uint16
    class*: uint16
    ttl*: int
    data*: seq[byte]

type DNSPacket* = object
    header*: DNSHeader
    questions*: seq[DNSQuestion]
    answers*: seq[DNSRecord]
    authorities*: seq[DNSRecord]
    additionals*: seq[DNSRecord]


func parse_header*(header_unparsed: seq[byte], offset: var int64): DNSHeader =
    var header = DNSHeader() 
    bigEndian16(addr header.id, addr header_unparsed[0])
    bigEndian16(addr header.flags, addr header_unparsed[2])
    bigEndian16(addr header.num_questions, addr header_unparsed[4])
    bigEndian16(addr header.num_answers, addr header_unparsed[6])
    bigEndian16(addr header.num_authorities, addr header_unparsed[8])
    bigEndian16(addr header.num_additionals,addr header_unparsed[10])
    offset = 12

    return header

proc decode_name*(dns_packet: seq[byte], offset: var int64): seq[byte]

proc decode_name_compressed*(dns_packet: seq[byte], offset: var int64): seq[byte] = 
    var pointer: int64 = cast[int64](((dns_packet[offset] and 0b00111111) shl 8) + dns_packet[offset+1])
    return decode_name(dns_packet, pointer)


proc decode_name*(dns_packet: seq[byte], offset: var int64): seq[byte] = 
    var parts: seq[string] = @[]
    while dns_packet[offset] != 0:
        if (dns_packet[offset] shr 6) == 0b11:
            parts.add(cast[string](decode_name_compressed(dns_packet, offset)))
            offset += 1
            break
        let
            length = cast[int8](dns_packet[offset])
            slice = dns_packet[offset+1..offset+length]
        parts.add(cast[string](slice))
        offset += length + 1
    offset += 1
    return cast[seq[byte]](parts.join("."))


proc parse_question*(packet: seq[byte], offset: var int64): DNSQuestion = 
    var
        question = DNSQuestion()
        name = decode_name(packet, offset)
    bigEndian16(addr question.`type`, addr packet[offset])
    bigEndian16(addr question.class, addr packet[offset+2])
    question.name = cast[seq[byte]](name)
    offset = offset + 4
    return question

proc parse_record*(dns_packet: seq[byte], offset: var int64): DNSRecord =
    var
        name = decode_name(dns_packet, offset)
        data_len: uint16
        record = DNSRecord(name: name)
    bigEndian16(addr record.`type`,   addr dns_packet[offset])
    bigEndian16(addr record.class,    addr dns_packet[offset+2])
    bigEndian32(addr record.ttl,      addr dns_packet[offset+4])
    bigEndian16(addr data_len, addr dns_packet[offset+8])
    record.data = dns_packet[offset+10..offset+10+int64(data_len)-1]
    offset += 10+int64(data_len)
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

proc ipv4_to_string*(data: seq[byte]): string =
    return data.join(".")

proc ipv6_to_string*(data: seq[byte]): string =
    return cast[string](data).toHex.insertSep(sep=':',digits=4)

