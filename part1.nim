import std/endians
import strutils
import std/random

type DNSHeader* = object
    id*: uint16
    flags*: uint16
    num_questions*: uint16 = 0
    num_answers*: uint16 = 0
    num_authorities*: uint16 = 0
    num_additionals*: uint16 = 0

type DNSQuestion* = object
    name*: seq[byte]
    `type`*: uint16
    class*: uint16

func to_bytes*(header: DNSHeader): seq[byte] =
    result = newSeq[byte](12)
    bigEndian16(addr result[0], addr header.id)
    bigEndian16(addr result[2], addr header.flags)
    bigEndian16(addr result[4], addr header.num_questions)
    bigEndian16(addr result[6], addr header.num_answers)
    bigEndian16(addr result[8], addr header.num_authorities)
    bigEndian16(addr result[10], addr header.num_additionals)

func to_bytes*(question: DNSQuestion): seq[byte] =
    result = newSeq[byte](question.name.len + 4)
    copyMem(addr result[0], addr question.name[0], question.name.len)
    bigEndian16(addr result[^4], addr question.`type`)
    bigEndian16(addr result[^2], addr question.class)

func encode_dns_name*(domain_name: string): seq[byte] =
    for i in domain_name.split("."):
        result.add(byte(len(i)))
        result.add(cast[seq[byte]](i))
    result.add(0)

const CLASS_IN = 1

proc build_query*(domain_name: string, record_type: uint16): seq[byte] =
    let
        name = encode_dns_name(domain_name)
        id: uint16 = uint16(rand(65535))
        RECURSION_DESIRED: uint16 = 1 shl 8
        header = DNSHeader(id: id, num_questions: 1, flags:RECURSION_DESIRED)
        question = DNSQuestion(name: name, `type`:record_type, class:CLASS_IN)
    
    return header.to_bytes() & question.to_bytes()
