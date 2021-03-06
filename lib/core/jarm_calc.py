# -*- coding: utf-8 -*-
# Version 1.0 (November 2020)
#
# Created by:
# John Althouse
# Andrew Smart
# RJ Nunaly
# Mike Brady
#
# Converted to Python by:
# Caleb Yu
#
# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause
#
# Version 1.1 for jarm_async (November 2020)
import struct
from typing import List, Union
from os import urandom
from random import choice as random_choice
from hashlib import sha256 as hashlib_sha256
__all__ = ['packet_building', 'read_packet', 'jarm_hash', 'CONST_SIZE_READ_BYTES']

CONST_SIZE_READ_BYTES = 1484


def packet_building(jarm_details: list) -> bytes:
    payload = b"\x16"
    #Version Check
    if jarm_details[2] == "TLS_1.3":
        payload += b"\x03\x01"
        client_hello = b"\x03\x03"
    elif jarm_details[2] == "SSLv3":
        payload += b"\x03\x00"
        client_hello =  b"\x03\x00"
    elif jarm_details[2] == "TLS_1":
        payload += b"\x03\x01"
        client_hello = b"\x03\x01"
    elif jarm_details[2] == "TLS_1.1":
        payload += b"\x03\x02"
        client_hello = b"\x03\x02"
    elif jarm_details[2] == "TLS_1.2":
        payload += b"\x03\x03"
        client_hello = b"\x03\x03"
    #Random values in client hello
    client_hello += urandom(32)
    session_id = urandom(32)
    session_id_length = struct.pack(">B", len(session_id))
    client_hello += session_id_length
    client_hello += session_id
    #Get ciphers
    cipher_choice = get_ciphers(jarm_details)
    client_suites_length = struct.pack(">H", len(cipher_choice))
    client_hello += client_suites_length
    client_hello += cipher_choice
    client_hello += b"\x01" #cipher methods
    client_hello += b"\x00" #compression_methods
    #Add extensions to client hello
    extensions = get_extensions(jarm_details)
    client_hello += extensions
    #Finish packet assembly
    inner_length = b"\x00"
    inner_length += struct.pack(">H", len(client_hello))
    handshake_protocol = b"\x01"
    handshake_protocol += inner_length
    handshake_protocol += client_hello
    outer_length = struct.pack(">H", len(handshake_protocol))
    payload += outer_length
    payload += handshake_protocol
    return payload


def choose_grease() -> bytes:
    """
    Randomly choose a grease value
    :return:
    """
    grease_list = [b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a", b"\x4a\x4a", b"\x5a\x5a", b"\x6a\x6a", b"\x7a\x7a", b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba", b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa"]
    return random_choice(grease_list)


def jarm_hash(jarm_raw: str) -> str:
    """

    :param jarm_raw:
    :return:
    """
    #If jarm is empty, 62 zeros for the hash
    if jarm_raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||":
        return "0"*62
    fuzzy_hash = ""
    handshakes = jarm_raw.split(",")
    alpns_and_ext = ""
    for handshake in handshakes:
        components = handshake.split("|")
        #Custom jarm hash includes a fuzzy hash of the ciphers and versions
        fuzzy_hash += cipher_bytes(components[0])
        fuzzy_hash += version_byte(components[1])
        alpns_and_ext += components[2]
        alpns_and_ext += components[3]
    #Custom jarm hash has the sha256 of alpns and extensions added to the end
    sha256 = (hashlib_sha256(alpns_and_ext.encode())).hexdigest()
    fuzzy_hash += sha256[0:32]
    return fuzzy_hash


def version_byte(version: str) -> str:
    """
    This captures a single version byte based on version
    :param version:
    :return:
    """
    if version == "":
        return "0"
    options = "abcdef"
    count = int(version[3:4])
    byte_str = options[count]
    return byte_str


def cipher_bytes(cipher: str) -> str:
    """

    :param cipher:
    :return:
    """
    if cipher == "":
        return "00"
    list_bytes = [b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f", b"\x00\x33", b"\x00\x35", b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67", b"\x00\x6b", b"\x00\x84", b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d", b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe", b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a", b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23", b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77", b"\xc0\x9c", b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2", b"\xc0\xa3",  b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf", b'\xcc\x13', b'\xcc\x14', b'\xcc\xa8', b'\xcc\xa9', b'\x13\x01', b'\x13\x02', b'\x13\x03', b'\x13\x04', b'\x13\x05']
    count = 1
    for byte_record in list_bytes:
        strtype_bytes = byte_record.hex()
        if cipher == strtype_bytes:
            break
        count += 1
    hexvalue = hex(count)[2:]
    #This part must always be two bytes
    if len(hexvalue) < 2:
        return_bytes = "0" + hexvalue
    else:
        return_bytes = hexvalue
    return return_bytes


def find_extension(ext_type: bytes, types, values):
    """
    Matching cipher extensions to values
    :param ext_type:
    :param types:
    :param values:
    :return:
    """
    iter = 0
    #For the APLN extension, grab the value in ASCII
    if ext_type == b"\x00\x10":
        while iter < len(types):
            if types[iter] == ext_type:
                return ((values[iter][3:]).decode())
            iter += 1
    else:
        while iter < len(types):
            if types[iter] == ext_type:
                return values[iter].hex()
            iter += 1
    return ""


def read_packet(data: Union[bytes, None]):
    """
    If a packet is received, decipher the details
    :param data:
    :return:
    """
    try:
        if not data:
            return "|||"
        jarm = ""
        #Server hello error
        if data[0] == 21:
            selected_cipher = b""
            return "|||"
        #Check for server hello
        elif (data[0] == 22) and (data[5] == 2):
            counter = data[43]
            #Find server's selected cipher
            selected_cipher = data[counter+44:counter+46]
            #Find server's selected version
            version = data[9:11]
            #Format
            jarm += str(selected_cipher.hex())
            jarm += "|"
            jarm += str(version.hex())
            jarm += "|"
            #Extract extensions
            extensions = (extract_extension_info(data, counter))
            jarm += extensions
            return jarm
        else:
            return "|||"

    except Exception as e:
        return "|||"


def extract_extension_info(data: bytes, counter):
    """
    Deciphering the extensions in the server hello
    :param data:
    :param counter:
    :return:
    """
    try:
        #Error handling
        if (data[counter+47] == 11):
            return "|||"
        elif (data[counter+50:counter+53] == b"\x0e\xac\x0b") or (data[82:85] == b"\x0f\xf0\x0b"):
            return "|||"
        count = 49+counter
        length = int.from_bytes(data[counter+47:counter+49], byteorder='big')
        maximum = length+(count-1)
        types = []
        values = []
        #Collect all extension types and values for later reference
        while count < maximum:
            types.append(data[count:count+2])
            ext_length = int.from_bytes(data[count+2:count+4], byteorder='big')
            if ext_length == 0:
                count += 4
                values.append("")
            else:
                values.append(data[count+4:count+4+ext_length])
                count += ext_length+4
        result = ""
        #Read application_layer_protocol_negotiation
        alpn = find_extension(b"\x00\x10", types, values)
        result += str(alpn)
        result += "|"
        #Add formating hyphens
        add_hyphen = 0
        while add_hyphen < len(types):
            result += types[add_hyphen].hex()
            add_hyphen += 1
            if add_hyphen == len(types):
                break
            else:
                result += "-"
        return result
    #Error handling
    except IndexError as e:
        result = "|||"
        return result


def extension_server_name(host: str) -> bytes:
    """
    Client hello server name extension
    :param host:
    :return:
    """
    ext_sni = b"\x00\x00"
    ext_sni_length = len(host)+5
    ext_sni += struct.pack(">H", ext_sni_length)
    ext_sni_length2 = len(host)+3
    ext_sni += struct.pack(">H", ext_sni_length2)
    ext_sni += b"\x00"
    ext_sni_length3 = len(host)
    ext_sni += struct.pack(">H", ext_sni_length3)
    ext_sni += host.encode()
    return ext_sni


def app_layer_proto_negotiation(jarm_details: List[int or str]) -> bytes:
    """
    Client hello apln extension
    :param jarm_details:
    :return:
    """
    ext = b"\x00\x10"
    if (jarm_details[6] == "RARE_APLN"):
        #Removes h2 and http/1.1
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30", b"\x06\x73\x70\x64\x79\x2f\x31", b"\x06\x73\x70\x64\x79\x2f\x32", b"\x06\x73\x70\x64\x79\x2f\x33", b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    else:
        #All apln extensions in order from weakest to strongest
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", b"\x06\x73\x70\x64\x79\x2f\x31", b"\x06\x73\x70\x64\x79\x2f\x32", b"\x06\x73\x70\x64\x79\x2f\x33" b"\x02\x68\x32", b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    #apln extensions can be reordered
    if jarm_details[8] != "FORWARD":
        alpns = cipher_mung(alpns, jarm_details[8])
    all_alpns = b""
    for alpn in alpns:
        all_alpns += alpn
    second_length = len(all_alpns)
    first_length = second_length+2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += all_alpns
    return ext


def key_share(grease: bool) -> bytes:
    """
    Generate key share extension for client hello
    :param grease:
    :return:
    """
    ext = b"\x00\x33"
    #Add grease value if necessary
    if grease == True:
        share_ext = choose_grease()
        share_ext += b"\x00\x01\x00"
    else:
        share_ext = b""
    group = b"\x00\x1d"
    share_ext += group
    key_exchange_length = b"\x00\x20"
    share_ext += key_exchange_length
    share_ext += urandom(32)
    second_length = len(share_ext)
    first_length = second_length+2
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">H", second_length)
    ext += share_ext
    return ext


def supported_versions(jarm_details: List[str or int], grease: bool) -> bytes:
    """
    Supported version extension for client hello
    :param jarm_details:
    :param grease:
    :return:
    """
    if (jarm_details[7] == "1.2_SUPPORT"):
        #TLS 1.3 is not supported
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
    else:
        #TLS 1.3 is supported
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    #Change supported version order, by default, the versions are from oldest to newest
    if jarm_details[8] != "FORWARD":
        tls = cipher_mung(tls, jarm_details[8])
    #Assemble the extension
    ext = b"\x00\x2b"
    #Add GREASE if applicable
    if grease == True:
        versions = choose_grease()
    else:
        versions = b""
    for version in tls:
        versions += version
    second_length = len(versions)
    first_length = second_length+1
    ext += struct.pack(">H", first_length)
    ext += struct.pack(">B", second_length)
    ext += versions
    return ext


def get_ciphers(jarm_details: list) -> bytes:
    """

    :param jarm_details:
    :return:
    """
    selected_ciphers = b""
    list_bytes = []
    #Two cipher lists: NO1.3 and ALL
    if jarm_details[3] == "ALL":
        list_bytes = [b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9", b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\x13\x05", b"\x13\x04", b"\x13\x03", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05"]
    elif jarm_details[3] == "NO1.3":
        list_bytes = [b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e", b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45", b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09", b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24", b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13", b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c", b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d", b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0", b"\x00\x07", b"\x00\x04", b"\x00\x05"]
    #Change cipher order
    assert list_bytes is not None
    if jarm_details[4] != "FORWARD":
        list_bytes = cipher_mung(list_bytes, jarm_details[4])
    #Add GREASE to beginning of cipher list (if applicable)
    if jarm_details[5] == "GREASE":
        list_bytes.insert(0,choose_grease())
    #Generate cipher list
    for cipher in list_bytes:
        selected_ciphers += cipher
    return selected_ciphers


def get_extensions(jarm_details: List[Union[str, int]]) -> bytes:
    """

    :param jarm_details:
    :return:
    """
    extension_bytes = b""
    all_extensions = b""
    grease = False
    #GREASE
    if jarm_details[5] == "GREASE":
        all_extensions += choose_grease()
        all_extensions += b"\x00\x00"
        grease = True
    #Server name
    all_extensions += extension_server_name(jarm_details[0])
    #Other extensions
    extended_master_secret = b"\x00\x17\x00\x00"
    all_extensions += extended_master_secret
    max_fragment_length = b"\x00\x01\x00\x01\x01"
    all_extensions += max_fragment_length
    renegotiation_info = b"\xff\x01\x00\x01\x00"
    all_extensions += renegotiation_info
    supported_groups = b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
    all_extensions += supported_groups
    ec_point_formats = b"\x00\x0b\x00\x02\x01\x00"
    all_extensions += ec_point_formats
    session_ticket = b"\x00\x23\x00\x00"
    all_extensions += session_ticket
    #Application Layer Protocol Negotiation extension
    all_extensions += app_layer_proto_negotiation(jarm_details)
    signature_algorithms = b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    all_extensions += signature_algorithms
    #Key share extension
    all_extensions += key_share(grease)
    psk_key_exchange_modes = b"\x00\x2d\x00\x02\x01\x01"
    all_extensions += psk_key_exchange_modes
    #Supported versions extension
    if (jarm_details[2] == "TLS_1.3") or (jarm_details[7] == "1.2_SUPPORT"):
        all_extensions += supported_versions(jarm_details, grease)
    #Finish assembling extensions
    extension_length = len(all_extensions)
    extension_bytes += struct.pack(">H", extension_length)
    extension_bytes += all_extensions
    return extension_bytes


def cipher_mung(ciphers: List[bytes], request: str) -> List[bytes]:
    """

    :param ciphers:
    :param request:
    :return:
    """
    output = []
    cipher_len = len(ciphers)
    #Ciphers backward
    if (request == "REVERSE"):
        output = ciphers[::-1]
    #Bottom half of ciphers
    elif (request == "BOTTOM_HALF"):
        if (cipher_len % 2 == 1):
            output = ciphers[int(cipher_len/2)+1:]
        else:
            output = ciphers[int(cipher_len/2):]
    #Top half of ciphers in reverse order
    elif (request == "TOP_HALF"):
        if (cipher_len % 2 == 1):
            output.append(ciphers[int(cipher_len/2)])
            #Top half gets the middle cipher
        output += cipher_mung(cipher_mung(ciphers, "REVERSE"),"BOTTOM_HALF")
    #Middle-out cipher order
    elif (request == "MIDDLE_OUT"):
        middle = int(cipher_len/2)
        # if ciphers are uneven, start with the center.  Second half before first half
        if (cipher_len % 2 == 1):
            output.append(ciphers[middle])
            for i in range(1, middle+1):
                output.append(ciphers[middle + i])
                output.append(ciphers[middle - i])
        else:
            for i in range(1, middle+1):
                output.append(ciphers[middle-1 + i])
                output.append(ciphers[middle - i])
    return output
