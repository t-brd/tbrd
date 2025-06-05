import argparse
import re
from dataclasses import dataclass
import ODID_enums as ODID
import numpy as np
import struct
import time
from datetime import datetime, timezone
from typing import List
import hashlib
import hmac
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp, sniff
import socket
import json
from  configparser import ConfigParser
from scapy.all import sniff, UDP, IP
import zmq
import messages_pb2

@dataclass
class BasicID:
    UAtype: int = 0
    IDtype: int = 0 
    UASID: str = ""
    raw: bytes = None

@dataclass
class Location:
    status: int = 0
    direction: float = 361           # Degrees. 0 <= x < 360. Route course based on true North. Invalid, No Value, or Unknown: 361deg
    SpeedHorizontal: float = 255     # m/s. Positive only. Invalid, No Value, or Unknown: 255m/s. If speed is >= 254.25 m/s: 254.25m/s
    SpeedVertical: float = 63        # m/s. Invalid, No Value, or Unknown: 63m/s. If speed is >= 62m/s: 62m/s
    Latitude:  int = 0               # Invalid, No Value, or Unknown: 0 deg (both Lat/Lon)
    Longitude: int = 0               # Invalid, No Value, or Unknown: 0 deg (both Lat/Lon)
    AltitudeBaro: float = -1000      # meter (Ref 29.92 inHg, 1013.24 mb). Invalid, No Value, or Unknown: -1000m
    AltitudeGeo: float = -1000       # meter (WGS84-HAE). Invalid, No Value, or Unknown: -1000m
    HeightType: int = 0
    Height: float = -1000            # meter. Invalid, No Value, or Unknown: -1000m
    HorizAccuracy: int = 0
    VertAccuracy: int = 0
    BaroAccuracy: int = 0
    SpeedAccuracy: int = 0
    TSAccuracy: int = 0
    TimeStamp: float = 0             # seconds after the full hour relative to UTC. Invalid, No Value, or Unknown: 0xFFFF 
    raw: bytes = None

@dataclass
class Auth:
    DataPage: int = 0
    AuthType: int = 0
    LastPageIndex: int = 0
    Length: int = 0 
    Timestamp: float = 0
    AuthData: int = 0
    raw: bytes = None

@dataclass
class System:
    LocationType: int = 0
    ClassificationType: int = 0
    OperatorLatitude: float = 0      # Invalid, No Value, or Unknown: 0 deg (both Lat/Lon)
    OperatorLongitude: float = 0     # Invalid, No Value, or Unknown: 0 deg (both Lat/Lon)
    AreaCount: int = 0               # Default 1
    AreaRadius: int = 0              # meter. Default 0
    AreaCeiling: int = 0             # meter. Invalid, No Value, or Unknown: -1000m
    AReaFloor: float = 0             # meter. Invalid, No Value, or Unknown: -1000m
    ClassEU: int = 0                 # Only filled if ClassificationType = ODID_CLASSIFICATION_TYPE_EU
    CategoryEU: int = 0              # Only filled if ClassificationType = ODID_CLASSIFICATION_TYPE_EU
    OperatorAltitudeGeo: float = 0   # meter (WGS84-HAE). Invalid, No Value, or Unknown: -1000m
    Timestamp: float = 0             # Relative to 00:00:00 01/01/2019 UTC/Unix Time
    raw: bytes = None

@dataclass
class Operator:
    OperatorIDType: int = 0
    OperatorID: str = ""
    raw: bytes = None

def tbrd_auth(payload, previous_hmac, key_disclosure):
    #Derive interval key
    key_prime = hashlib.sha512(key_disclosure).hexdigest()
    key_prime = bytes(key_prime[:64],'utf-8')

    tbrd_hmac_calc = hmac.new(key_prime,payload,hashlib.sha256).digest()

    if tbrd_hmac_calc == previous_hmac:
        print("Previous Message is VALID")
    else:
        print("Previous message is NOT VALID")
        print(f'HMAC Calculated: {tbrd_hmac_calc}')
        print(f'HMAC disclosed: {previous_hmac}')

def decodeMsgPack(encodedmessage):
    """Decodes a 203-byte Message Pack bytearray into its component messages."""

    if len(encodedmessage) != 203:
        raise ValueError("Invalid message length. Expected 203 bytes.")

    # Extract header information
    header = encodedmessage[0]
    message_type = (header >> 4) & 0x0F  # Extract upper 4 bits
    protocol_version = header & 0x0F  # Extract lower 4 bits

    # Extract message size
    size = encodedmessage[1]

    # Extract number of messages in the pack
    num_msgs = encodedmessage[2]

    # Validate expected message count
    if num_msgs != 8:
        print(num_msgs)
        raise ValueError("Unexpected number of messages in pack. Expected 8")

    # Extract individual messages (each message is 25 bytes)
    messages = []
    offset = 3
    for i in range(num_msgs):
        messages.append(encodedmessage[offset:offset+25])
        offset += 25

    # Return parsed data
    return {
        "message_type": message_type,
        "protocol_version": protocol_version,
        "message_size": size,
        "num_messages": num_msgs,
        "messages": messages
    }

def decodeBasicID(encodedmessage):
    '''Decodes a byte payload into a BasicID object'''

    # Extract ID type and UA type [4 bits, IDType] [4 bits, UAType]
    IDtype = (encodedmessage[1] >> 4) & 0xF
    UAtype = encodedmessage[1] & 0xF

    # Extract UASID [20 bytes, null-padded]
    uasid_bytes = encodedmessage[2:22]
    uasid = uasid_bytes.rstrip(b'\x00').decode('utf-8')

    # Validate UASID if ID type is CAA Registration ID
    if IDtype == ODID.ODID_idtype.ODID_IDTYPE_CAA_REGISTRATION_ID:
        if not re.fullmatch(r'[A-Z0-9.]+', uasid):
            raise ValueError("Decoded UASID contains invalid characters.")

    return BasicID(UAtype=UAtype, IDtype=IDtype, UASID=uasid, raw=encodedmessage)


def decode_lat_long(encoded_bytes):
    """Decodes latitude and longitude from a 4-byte encoded value."""
    return struct.unpack('<i', encoded_bytes)[0] / 1e7

def decodeLocation(encodedmessage):
    '''Decodes a byte payload into a Location object'''
    
    # Decode Header
    Header = encodedmessage[0]
    MessageType = (Header >> 4) & 0x0F
    ProtocolVersion = Header & 0x0F
    
    # Decode Status and Flags
    Status_Flags = encodedmessage[1]
    Status = (Status_Flags >> 4) & 0x0F
    HeightType = (Status_Flags >> 2) & 0x01
    E_W_Direction = (Status_Flags >> 1) & 0x01
    SpeedMultiplier = Status_Flags & 0x01
    
    # Decode Track Direction
    direction = encodedmessage[2]
    if E_W_Direction == 1:
        direction += 180
    
    # Decode Horizontal Speed
    speed = encodedmessage[3]
    if speed <= 255:
        SpeedHorizontal = speed * 0.25
    else:
        SpeedHorizontal = (speed * 0.75) + (255 * 0.25)
    
    # Decode Vertical Speed (Int8 signed)
    SpeedVertical = struct.unpack('b', bytes([encodedmessage[4]]))[0] * 0.5
    
    # Decode Latitude and Longitude
    Latitude = decode_lat_long(encodedmessage[5:9])
    Longitude = decode_lat_long(encodedmessage[9:13])
    
    # Decode Pressure Altitude
    p_alt = struct.unpack('<h', encodedmessage[13:15])[0]
    AltitudeBaro = (p_alt * 0.5) - 1000 if p_alt != 0 else -1000
    
    # Decode Geodetic Altitude
    g_alt = struct.unpack('<h', encodedmessage[15:17])[0]
    AltitudeGeo = (g_alt * 0.5) - 1000 if g_alt != 0 else -1000
    
    # Decode Height
    height = struct.unpack('<h', encodedmessage[17:19])[0]
    Height = (height * 0.5) - 100 if height != 0 else -100
    
    # Decode Vertical and Horizontal Accuracy
    vh_accuracy = encodedmessage[19]
    VertAccuracy = (vh_accuracy >> 4) & 0x0F
    HorizAccuracy = vh_accuracy & 0x0F
    
    # Decode BaroAlt and Speed Accuracy
    bs_accuracy = encodedmessage[20]
    BaroAccuracy = (bs_accuracy >> 4) & 0x0F
    SpeedAccuracy = bs_accuracy & 0x0F
    
    # Decode Timestamp
    timestamp = struct.unpack('<h', encodedmessage[21:23])[0]
    TimeStamp = timestamp  # Represents tenths of a second since last hour UTC
    
    # Decode Timestamp Accuracy
    res_t_accuracy = encodedmessage[23]
    TSAccuracy = res_t_accuracy & 0x0F
    
    return Location(
        status=Status,
        direction=direction,
        SpeedHorizontal=SpeedHorizontal,
        SpeedVertical=SpeedVertical,
        Latitude=Latitude,
        Longitude=Longitude,
        AltitudeBaro=AltitudeBaro,
        AltitudeGeo=AltitudeGeo,
        HeightType=HeightType,
        Height=Height,
        HorizAccuracy=HorizAccuracy,
        VertAccuracy=VertAccuracy,
        BaroAccuracy=BaroAccuracy,
        SpeedAccuracy=SpeedAccuracy,
        TSAccuracy=TSAccuracy,
        TimeStamp=TimeStamp,
        raw=encodedmessage
    )

def decodeSystem(encodedmessage: bytearray) -> System:
    """Decodes a byte payload from a wifi beacon into a System dataclass instance."""
    
    if len(encodedmessage) != 25:
        raise ValueError("Invalid message length, expected 25 bytes")

    # Decode System header
    header = encodedmessage[0]
    message_type = (header >> 4) & 0x0F  # Not needed for System object
    protocol_version = header & 0x0F  # Not stored in System dataclass

    # Decode Flags
    flags = encodedmessage[1]
    classification_type = (flags >> 2) & 0x07
    location_type = flags & 0x03

    # Decode Latitude and Longitude
    operator_latitude = decode_lat_long(encodedmessage[2:6])
    operator_longitude = decode_lat_long(encodedmessage[6:10])

    # Decode Area Count
    area_count = struct.unpack('<H', encodedmessage[10:12])[0]

    # Decode Area Radius
    area_radius = encodedmessage[12] // 10  # Convert back from encoding

    # Decode Area Ceiling
    area_ceiling = struct.unpack('<H', encodedmessage[13:15])[0]
    area_ceiling = (area_ceiling * 0.5) - 1000  # Reverse encoding

    # Decode Area Floor
    area_floor = struct.unpack('<H', encodedmessage[15:17])[0]
    area_floor = (area_floor * 0.5) - 1000  # Reverse encoding

    # Decode UA Classification
    class_eu, category_eu = 0, 0
    if classification_type == 1:  # Only if ClassificationType is EU
        classification = encodedmessage[17]
        category_eu = (classification >> 4) & 0x0F
        class_eu = classification & 0x0F

    # Decode Operator Altitude
    operator_altitude_geo = struct.unpack('<H', encodedmessage[18:20])[0]
    operator_altitude_geo = (operator_altitude_geo * 0.5) - 1000  # Reverse encoding

    # Decode Timestamp
    timestamp = struct.unpack('<I', encodedmessage[20:24])[0]

    # Return a System dataclass instance
    return System(
        LocationType=location_type,
        ClassificationType=classification_type,
        OperatorLatitude=operator_latitude,
        OperatorLongitude=operator_longitude,
        AreaCount=area_count,
        AreaRadius=area_radius,
        AreaCeiling=area_ceiling,
        AReaFloor=area_floor,
        ClassEU=class_eu,
        CategoryEU=category_eu,
        OperatorAltitudeGeo=operator_altitude_geo,
        Timestamp=timestamp,
        raw=encodedmessage
    )

def decodeOperator(encodedmessage: bytearray) -> Operator:
    """Decodes a byte payload and extracts Operator ID Type and Operator ID."""
    
    if len(encodedmessage) < 25:
        raise ValueError("Invalid message length. Expected at least 25 bytes.")

    # Extract Operator ID Type (Second Byte)
    operatorIDtype = encodedmessage[1]

    # Extract Operator ID (Remaining Bytes until first null byte or max length)
    operatorID_bytes = encodedmessage[2:25]  # Max length for ID field
    operatorID = operatorID_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='ignore')

    # Return as an Operator dataclass instance
    return Operator(OperatorIDType=operatorIDtype, OperatorID=operatorID, raw=encodedmessage)

def decodeAuth(encodedmessage: bytearray) -> Auth:
    '''Decodes an Authentication message from a byte payload'''

    if len(encodedmessage) < 2:
        raise ValueError("Encoded message is too short to be valid.")

    # Extract Authentication header
    header = encodedmessage[0]
    message_type = (header & 0xF0) >> 4  # Upper 4 bits
    protocol_version = header & 0x0F  # Lower 4 bits

    # Extract Auth Type and Page Number
    type_page = encodedmessage[1]
    auth_type = (type_page & 0xF0) >> 4  # Upper 4 bits
    data_page = type_page & 0x0F  # Lower 4 bits

    last_page_index = 0
    length = 0
    timestamp = 0
    auth_data = b''

    if data_page == 0:
        # Extract Last Page Index
        index = encodedmessage[2]
        last_page_index = index & 0x0F  # Lower 4 bits

        # Extract Length
        length = encodedmessage[3]

        # Extract Timestamp (assuming it's a 4-byte integer)
        timestamp = struct.unpack(">I", encodedmessage[4:8])[0]  # Convert bytes to integer

        # Extract Authentication Data
        auth_data = bytes(encodedmessage[8:8+length])

    else:
        # Extract Authentication Data for pages other than 0
        auth_data = bytes(encodedmessage[2:])

    # Return the decoded data as an Auth dataclass instance
    return Auth(
        DataPage=data_page,
        AuthType=auth_type,
        LastPageIndex=last_page_index,
        Length=len(auth_data),
        Timestamp=timestamp,
        AuthData=auth_data,
        raw=encodedmessage
    )

def send_query(operator_id, uas_id, timestamp, uss_ip, uss_port):

    # Prepare our context
    context = zmq.Context()

    # Create the request data message
    request_data = messages_pb2.RequestData()
    request_data.Operator_ID = operator_id
    request_data.UAS_ID = uas_id
    request_data.Time = timestamp

    # Create the sending sockt to send data 
    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(uss_ip, uss_port))

    # Send request data message
    client.send(b'REQUEST_DATA',flags=zmq.SNDMORE)
    client.send(request_data.SerializeToString())

    # Wait for response
    message = client.recv_multipart()
    
    # Print key commitment if valid record
    if message[0] == b'REPLY_DATA':
        data_reply = messages_pb2.ReplyData()
        data_reply.ParseFromString(message[1])
        return [data_reply.KeyCommit,data_reply.Start]

    # Print response if some error
    elif message[0] == b'ERROR':
        print("Error from server\n")
        error_message = messages_pb2.SendError()
        error_message.ParseFromString(message[1])
        print(error_message.ErrorCode)
        return 0
    
    else:
        print("Unknown message from server")
        return 0

def verify_commitment(key_USS, mission_start, key_observed, interval, timestamp):

    if key_USS == key_observed.hex():
        print('\nWARNING - Root Key is being used to authenticate remote ID Message <-- This is BAD!!!')
        return
    
    #Verify Proper Key Chain in use
    hash_key = key_observed
    for i in range(interval-1):
        hash_key = hashlib.sha256(bytes(hash_key)).digest() 

    if hash_key.hex() == key_USS:
            print('\nKey chain in use is VALID')
    else:
        print('\nKey chain in use is NOT valid')
        print(hash_key.hex())
        print(key_USS)
        return
    
    #Verify proper interval
    observed_k0_time = timestamp - interval

    if observed_k0_time < mission_start:
        print("\nInterveral key use check is VALID")
    else:
        print("\nInterval key use is NOT valid, interval key re-use detected")
        print(mission_start)
        print(observed_k0_time)

def decode_vend_payload(payload):

    oui = payload[0:3].hex().upper()
    vendor_type = payload[3]
    counter = int.from_bytes(payload[4:5], byteorder='big')
    data = payload[5:]
    msgpack = decodeMsgPack(data)

    #Decode BasicID
    basicid_dec = BasicID()
    basicid_dec = decodeBasicID(msgpack["messages"][0])

    #Decode Location
    location_dec = Location()
    location_dec = decodeLocation(msgpack["messages"][1])

    #Decode System Message
    system_dec = System()
    system_dec = decodeSystem(msgpack["messages"][6])

    #Decode Operator ID message
    operator_dec = Operator()
    operator_dec = decodeOperator(msgpack["messages"][7])

    #Decode Auth message 0
    auth0_dec = Auth()
    auth0_dec = decodeAuth(msgpack["messages"][2])

    #Decode Auth message 1
    auth1_dec = Auth()
    auth1_dec = decodeAuth(msgpack["messages"][3])
       
    #Decode Auth message 2
    auth2_dec = Auth()
    auth2_dec = decodeAuth(msgpack["messages"][4])
     
    #Decode Auth message 3
    auth3_dec = Auth()
    auth3_dec = decodeAuth(msgpack["messages"][5])

    return {
        "OUI": oui,
        "Vendor Type": f"0x{vendor_type:02X}",
        "Counter": counter,
        "Payload Length": len(payload),
        "Messages": {"BasicID": basicid_dec,
                     "Location": location_dec,
                     "Operator": operator_dec,
                     "System": system_dec,
                     "Auth0": auth0_dec,
                     "Auth1": auth1_dec,
                     "Auth2": auth2_dec,
                     "Auth3": auth3_dec}
            }

def decode_tbrd_auth_message(auth0, auth1, auth2, auth3):

    auth_message = auth0.AuthData + auth1.AuthData + auth2.AuthData + auth3.AuthData
    interval = auth_message[0:4]
    tbrd_hmac = auth_message[4:36]
    key_disclosure = auth_message[36:68]
    
    return{
        "Interval": int.from_bytes(interval,byteorder="big"),
        "HMAC": tbrd_hmac,
        "Key_Disclosure": key_disclosure
        }

def sniff_udp(interface, port, uss_ip, uss_port, verbose):

    print(f"Sniffing UDP packets on interface {interface} port {port}... Press Ctrl+C to stop.\n")

    # Buffer to store the previous beacon
    previous = {'Payload': None, 'HMAC': None, 'Key_Disclosure': None, 'Interval': None, 'Received_Time': None, 'Hash': None}

    def handle_packet(pkt):
        if UDP in pkt and pkt[UDP].dport == port:
            timestamp = time.time()
            ip_layer = pkt[IP]
            payload = bytes(pkt[UDP].payload)
   
            # Compute a hash of the payload for deduplication (issue when usign loopback)
            current_hash = hashlib.sha256(payload).hexdigest()

            # If the hash matches the previous, skip processing
            if current_hash == previous.get('Hash'):
                return  
            
            # Decode payload
            decoded = decode_vend_payload(payload)
            print(f"\n[{timestamp:.6f}] Message from {ip_layer.src}:{pkt[UDP].sport}")

            #Decode TBRD auth message
            tbrd_auth_msg = decode_tbrd_auth_message(decoded['Messages']['Auth0'],decoded['Messages']['Auth1'],decoded['Messages']['Auth2'],decoded['Messages']['Auth3'])

            if verbose==True:
                print('\nTBRD Auth Message received:')
                print(f'Interval: {tbrd_auth_msg.get("Interval")}')
                print(f'HMAC: {tbrd_auth_msg["HMAC"].hex()}')
                print(f'Key_Disclosure: {tbrd_auth_msg["Key_Disclosure"].hex()}')

            if previous['Payload'] != None:
                #Authenticate previous packet
                if verbose ==True:
                    print("\nAuthenticating previously received message: ")
                    print(f'Previous Payload: {previous["Payload"].hex()}')
                    print(f'Previous HMAC: {previous["HMAC"].hex()}')
                    print(f'Key Disclosed this interval: {tbrd_auth_msg["Key_Disclosure"].hex()}')
                
                tbrd_auth(previous['Payload'],previous['HMAC'],tbrd_auth_msg['Key_Disclosure'])
                

                #send query to USS
                if verbose == True:
                    print("Retreiving commitment data from USS:")
                    print(f"Sending Operator ID: {decoded['Messages']['Operator'].OperatorID}")
                    print(f"Sending UAS ID: {decoded['Messages']['BasicID'].UASID}")
                    print(f"Sending Timestamp: {timestamp}")

                [key_commit, start] = send_query(decoded['Messages']['Operator'].OperatorID,decoded['Messages']['BasicID'].UASID,timestamp, uss_ip, uss_port)
                
                if verbose == True:
                    print("\nResponse from USS:")
                    print(f"Key Commitment received from USS: {key_commit}")
                    print(f"Start time received from USS: {start}")

                #validate commitment
                verify_commitment(key_commit, start, previous['Key_Disclosure'], previous['Interval'], previous['Received_Time'])

            # Update the buffer
            previous['Payload'] = (
                tbrd_auth_msg['Interval'].to_bytes(4, 'big') +
                decoded['Messages']['BasicID'].raw +
                decoded['Messages']['Location'].raw +
                decoded['Messages']['System'].raw +
                decoded['Messages']['Operator'].raw
            )
            previous['HMAC'] = tbrd_auth_msg['HMAC']
            previous['Key_Disclosure'] = tbrd_auth_msg['Key_Disclosure']
            previous['Interval'] = tbrd_auth_msg['Interval']
            previous['Received_Time'] = timestamp
            previous['Hash'] = current_hash 
            

    sniff(filter=f"udp port {port}", prn=handle_packet, store=0, iface=interface)

def sniff_wifi(interface, target_bssid, verbose):

    # Buffer to store the previous beacon
    previous = {'Payload': None, 'HMAC': None, 'Key_Disclosure': None, 'Interval': None, 'Received_Time': None, 'Hash': None}

    def handle_packet(pkt):
        if pkt.haslayer(Dot11Beacon) and pkt.addr2 == target_bssid:
            timestamp = time.time()

            #
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 221:  # Vendor Specific Element ID
                    vendor_data = elt.info
                    if len(vendor_data) >= 3:
                        payload = vendor_data  # Remaining data
                elt = elt.payload.getlayer(Dot11Elt)
            
            #Decode payload
            decoded = decode_vend_payload(payload)
            print(f"\n[{timestamp:.6f}] From {target_bssid}")

            #Decode TBRD auth message
            tbrd_auth_msg = decode_tbrd_auth_message(decoded['Messages']['Auth0'],decoded['Messages']['Auth1'],decoded['Messages']['Auth2'],decoded['Messages']['Auth3'])

            if verbose==True:
                print('\nTBRD Auth Message received:')
                print(f'Interval: {tbrd_auth_msg.get("Interval")}')
                print(f'HMAC: {tbrd_auth_msg["HMAC"].hex()}')
                print(f'Key_Disclosure: {tbrd_auth_msg["Key_Disclosure"].hex()}')

            if previous['Payload'] != None:
                #Authenticate previous packet
                if verbose ==True:
                    print("\nAuthenticating previously received message: ")
                    print(f'Previous Payload: {previous["Payload"].hex()}')
                    print(f'Previous HMAC: {previous["HMAC"].hex()}')
                    print(f'Key Disclosed this interval: {tbrd_auth_msg["Key_Disclosure"].hex()}')
                
                tbrd_auth(previous['Payload'],previous['HMAC'],tbrd_auth_msg['Key_Disclosure'])
                

                #send query to USS
                if verbose == True:
                    print("Retreiving commitment data from USS:")
                    print(f"Sending Operator ID: {decoded['Messages']['Operator'].OperatorID}")
                    print(f"Sending UAS ID: {decoded['Messages']['BasicID'].UASID}")
                    print(f"Sending Timestamp: {timestamp}")

                [key_commit, start] = send_query(decoded['Messages']['Operator'].OperatorID,decoded['Messages']['BasicID'].UASID,timestamp, uss_ip, uss_port)
                
                if verbose == True:
                    print("\nResponse from USS:")
                    print(f"Key Commitment received from USS: {key_commit}")
                    print(f"Start time received from USS: {start}")

                #validate commitment
                verify_commitment(key_commit, start, previous['Key_Disclosure'], previous['Interval'], previous['Received_Time'])

            # Update the buffer
            previous['Payload'] = (
                tbrd_auth_msg['Interval'].to_bytes(4, 'big') +
                decoded['Messages']['BasicID'].raw +
                decoded['Messages']['Location'].raw +
                decoded['Messages']['System'].raw +
                decoded['Messages']['Operator'].raw
            )
            previous['HMAC'] = tbrd_auth_msg['HMAC']
            previous['Key_Disclosure'] = tbrd_auth_msg['Key_Disclosure']
            previous['Interval'] = tbrd_auth_msg['Interval']
            previous['Received_Time'] = timestamp

    # Pass user-specified BSSID to `extract_vendor_elements`
    sniff(
        iface=interface,
        prn=handle_packet,
        store=0,  # don't store all packets in memory
        lfilter=lambda pkt: pkt.haslayer(Dot11Beacon)
    )

# Main Execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniff Wi-Fi Beacons from a specific BSSID and extract Vendor-Specific Elements")
    parser.add_argument("-v","--verbose",action='store_true',help="Verbose output for debugging")
    parser.add_argument("-u","--udp",action='store_true',help="Sniff TBRD over UDP")
    parser.add_argument('-c','--config', type=str, default='tx_config.ini', help="Config filepath")
    args = parser.parse_args()

    #Load config
    config = ConfigParser()
    try:
        config.read(args.config)
    except:
        print("Unable to load config file")
    
    #TODO: Add some config error checking

    interface = config['Rx']['interface']
    bssid = config['Rx']['bssid']
    udp_interface = config['Rx']['udp_interface']
    udp_port = int(config['Rx']['udp_port'])
    uss_ip = config['USS']['ip']
    uss_port = int(config['USS']['port'])

    if args.udp:
        sniff_udp(udp_interface, udp_port, uss_ip, uss_port, args.verbose)
    else:
        sniff_wifi(interface, bssid, args.verbose)
