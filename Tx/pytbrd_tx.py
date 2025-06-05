from dataclasses import dataclass
import ODID_enums as ODID
import re
import numpy as np
import struct
import time
from datetime import datetime, timezone
from typing import List
import hashlib
import hmac
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp
from  configparser import ConfigParser
from pymavlink import mavutil
import secrets
import argparse
import socket
import messages_pb2
import zmq
import threading

PROTOCOL_VER = 2
MESSAGE_SIZE = 25
NUM_KEYS = 500 #Default number of tesla keys if keyfile not provided
KEY_OUTPUT_FILE = 'interval_keys_tx'
T = 1 #transmission interval
E = .25 #transmission backoff

# === Shared Message Buffer ===
latest_messages = {
    'BASIC_ID': None,
    'LOCATION': None,
    'SYSTEM': None,
    'OPERATOR': None
}
buffer_lock = threading.Lock()

@dataclass
class BasicID:
    UAtype: int = 0
    IDtype: int = 0 
    UASID: str = ""

@dataclass
class Location:
    status: int = 0
    direction: int = 361           # Degrees. 0 <= x < 360. Route course based on true North. Invalid, No Value, or Unknown: 361deg
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

@dataclass
class Auth:
    DataPage: int = 0
    AuthType: int = 0
    LastPageIndex: int = 0
    Length: int = 0 
    Timestamp: float = 0
    AuthData: int = 0

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

@dataclass
class Operator:
    OperatorIDType: int = 0
    OperatorID: str = ""

@dataclass
class UASdata:
    basicID_data: BasicID
    location_data: Location
    auth_data: List[Auth]
    system_data: System
    operatorID_data: Operator

    @property
    def total_messages(self) -> int:
        """Returns the total number of objects in UASdata, considering lists."""
        return 4 + len(self.auth_data)  # 4 single objects + number of Auth objects

def concat_nybble(nybble1: int, nybble2: int) -> int:
    '''Takes two nybbles and concatenates them per ASTM F3411-22a'''
    if not (0x0 <= nybble1 <= 0xF):
        raise ValueError("Message type must be between 0x0 and 0xF")
    
    if not (0x0 <= nybble2 <= 0xF):
        raise ValueError("Protocol version must be between 0x0 and 0xF")

    header = (nybble1 << 4) | nybble2
    return header

def encode_lat_long(lat_long):
    # Multiply by 10^7 and convert to an integer
    lat_long_int = int(lat_long)
    
    # Pack into 4 bytes using little-endian format
    encoded_bytes = struct.pack('<i', lat_long_int)  # '<i' means little-endian signed 4-byte integer
    
    return encoded_bytes

def tenths_since_last_hour_utc():
    now = datetime.now(timezone.utc)
    seconds_since_last_hour = (now.minute * 60) + now.second
    tenths_of_seconds = (seconds_since_last_hour * 10) + (now.microsecond // 100000)
    
    # Ensure value fits within 16-bit unsigned integer
    tenths_of_seconds = tenths_of_seconds & 0xFFFF
    
    # Encode as little-endian 16-bit unsigned integer
    return struct.pack('<H', tenths_of_seconds)

def unix_timestamp_since_2019():
    """
    Returns the current time as a 32-bit Unix timestamp (UTC) in seconds 
    since the epoch 00:00:00 01/01/2019.
    """
    unix_time = int(time.time())  # Standard Unix timestamp since 1970
    offset = 1546300800  # Unix timestamp for 00:00:00 01/01/2019
    timestamp = unix_time - offset
    timestamp = timestamp & 0xFFFFFFFF
    return struct.pack('<I',timestamp)

def load_keys_from_file(filename):
    try:
        with open(filename, "r") as file:
            keys = [bytes.fromhex(line.strip()) for line in file.readlines()]
        return keys
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        return []


def encodeBasicID(data: BasicID):
    '''Encodes BasicID data into a byte payload for transmission via wifi beacon'''
    # Initialize message buffer
    encodedmessage = bytearray(25)

    #Basic ID header [4bits, Message Type][4bits, Protocol Version]
    Header = concat_nybble(int(ODID.ODID_messagetype.BASIC_ID), PROTOCOL_VER)
    encodedmessage[0] = Header

    #Encode IDtype and UAType [4bits, IDType][4bits, UAType]
    Header = concat_nybble(data.IDtype,data.UAtype)
    encodedmessage[1] = Header
    
    #Encode UASID [20 bytes, padded with nulls]
    if (data.IDtype == ODID.ODID_idtype.ODID_IDTYPE_CAA_REGISTRATION_ID):
        if not (re.fullmatch(r'[A-Z0-9.]+',data.UASID)):
            raise ValueError("A CAA Registraiton ID used as the UASID can only contain A-F,0-9, and (.)")
        uasid = data.UASID
        uasid = uasid.encode('utf-8')
        encodedmessage[2:2+len(uasid)] = uasid

    if args.verbose:
        print(f'BasidID:           {encodedmessage.hex()}')
    
    return encodedmessage

def encodeLocation(data: Location):
    '''Encodes Location/Vector data into a byte payload for transmission via wifi beacon'''
    #Initialize message buffer
    encodedmessage = bytearray(25)
    #print(encodedmessage.hex())

    #Location ID header [4bits, Message Type][4bits, Protocol Version]
    Header = concat_nybble(int(ODID.ODID_messagetype.LOCATION), PROTOCOL_VER)
    encodedmessage[0] = Header

    #Encode Status and Flags [4 bits, Status][1 bit, reserved][1 bit, Height Type][1 bit, E/W Direction Segment][1 bit Speed Multiplier]
    status = data.status
    reserved_bit = 0
    height_bit = int(data.HeightType)

    #E/W Direction Segment Bit, 0: <180, 1>= 180
    if data.direction < 180: 
        e_w_direction_bit = 0
    else: e_w_direction_bit = 1

    #Speed Multiplier enables speeds up to 254.25 m ⁄s. Only use 1 when speed exceeds 63.75 m ⁄s and add 63.75.
    if data.SpeedHorizontal > 63.75:
        speed_mult_bit = 1
    else: speed_mult_bit = 0

    Status_Flags = (status << 4) | (reserved_bit << 3) | (height_bit << 2) | (e_w_direction_bit << 1) | speed_mult_bit
    #print(format(Status_Flags,'02x'))
    encodedmessage[1] = Status_Flags
    #print(encodedmessage.hex())

    #Encode Track Direction
    if data.direction/100 <180:
        direction = data.direction/100
    else: direction = (data.direction/100)-180    

    #print(format(direction,'02x'))
    encodedmessage[2] = int(direction)

    #print(encodedmessage.hex())
    #Encode Horizontal Speed
    if data.SpeedHorizontal <= (255*.25):
        speed = round(data.SpeedHorizontal/.25)
    elif (data.SpeedHorizontal > (255*.25)) & (data.SpeedHorizontal < 254.25):
        speed = round((data.SpeedHorizontal-(255*.25))/.75)
    else:
        speed = 254

    #print(format(speed,'02x'))
    encodedmessage[3] = speed
    #print(encodedmessage.hex())

    #Encode Vertical Speed as 8 bit signed int (Int8) EncodedValue = Value / 0.5
    vert_speed = round(data.SpeedVertical/.5)
    vert_speed = int(vert_speed & 0xFF) #Convert to 2's compliment representation using 0xFF mask
    #print(format(vert_speed,'02x'))
    encodedmessage[4] = vert_speed
    #print(encodedmessage.hex())

    #Encode Latitude
    latitude = encode_lat_long(data.Latitude)
    encodedmessage[5:5+len(latitude)] = latitude
    #print(encodedmessage.hex())

    #Encode Longitude
    #print(longitude.hex())
    longitude = encode_lat_long(data.Longitude)
    encodedmessage[9:9+len(longitude)] = longitude
    #print(encodedmessage.hex())

    #Encode Pressure Altitude
    if data.AltitudeBaro == -1000: p_alt = 0
    else : p_alt = int((round(data.AltitudeBaro + 1000)/.5))
    p_alt = struct.pack('<h',p_alt)
    #print(p_alt.hex())
    encodedmessage[13:13+len(p_alt)] = p_alt
    #print(encodedmessage.hex())  

    #Encode Pressure Geodetic
    if data.AltitudeGeo == -1000: g_alt = 0
    else : g_alt = int((round(data.AltitudeGeo + 1000)/.5))
    g_alt = struct.pack('<h',g_alt)
    #print(g_alt.hex())
    encodedmessage[15:15+len(g_alt)] = g_alt
    #print(encodedmessage.hex())

    #Encode Height
    if data.Height == -100: height = 0
    else : height= int((round(data.Height + 1000)/.5))
    height = struct.pack('<h',height)
    #print(height.hex())
    encodedmessage[17:17+len(height)] = height
    #print(encodedmessage.hex())

    #Encode Vertical/Horz Accuracy [4 bits, Vertical Accuracy][4 bits, Horizontal Accuracy]
    vh_accuracy = concat_nybble(int(data.VertAccuracy), int(data.HorizAccuracy))
    #print(format(vh_accuracy,'02x'))
    encodedmessage[19] = vh_accuracy
    #print(encodedmessage.hex())

    #Encode BaroAlt/Speed Accuracy [4 bits, Baro Alt Accuracy][4 bits, Speed Accuracy]
    bs_accuracy = concat_nybble(int(data.BaroAccuracy), int(data.SpeedAccuracy))
    #print(format(bs_accuracy,'02x'))
    encodedmessage[20] = bs_accuracy
    #print(encodedmessage.hex())

    #Encode Timestamp
    timestamp = tenths_since_last_hour_utc()
    #print(timestamp.hex())
    encodedmessage[21:21+len(timestamp)] = timestamp
    #print(encodedmessage.hex())

    #Encode Timestamp Accuracy [4 bits, reserved][4 bits, Timestamp Accuracy]
    res_t_accuracy = concat_nybble(0, int(data.TSAccuracy))
    #print(format(res_t_accuracy,'02x'))
    encodedmessage[23] = res_t_accuracy

    if args.verbose:
        print(f'Location:          {encodedmessage.hex()}') 

    #Last Byte reserved

    return encodedmessage

def encodeSystem (data: System):
    '''Encodes System data into a byte payload for transmission via wifi beacon'''
    #Initialize message buffer
    encodedmessage = bytearray(25)
    #print(encodedmessage.hex())

    #System header [4bits, Message Type][4bits, Protocol Version]
    Header = concat_nybble(int(ODID.ODID_messagetype.SYSTEM), PROTOCOL_VER)
    encodedmessage[0] = Header
    
    #Encode Flags [3 bits, reserved][3 bits, Classification Type][2 bits, Operator Loc/Alt source]
    reserved_bit = 0
    classification_type = int(data.ClassificationType)
    source = int(data.LocationType)
    Flags = (reserved_bit << 7) | (classification_type << 2) | source

    #print(format(Flags,'02x'))
    encodedmessage[1] = Flags

    #Encode Latitude
    latitude = encode_lat_long(data.OperatorLatitude)
    #print(latitude.hex())
    encodedmessage[2:2+len(latitude)] = latitude
    #print(encodedmessage.hex())

    #Encode Longitude
    longitude = encode_lat_long(data.OperatorLongitude)
    #print(longitude.hex())
    encodedmessage[6:6+len(longitude)] = longitude
    #print(encodedmessage.hex())

    #Encode Area Count
    count = int(data.AreaCount)
    count = struct.pack('<H',count)
    #print(count.hex())
    encodedmessage[10:10+len(count)] = count
    #print(encodedmessage.hex())

    #Encode Area Radius
    radius = int(data.AreaRadius)
    radius = radius / 10
    #print(format(radius,'02x'))
    encodedmessage[12] = int(radius)
    #print(encodedmessage.hex())

    #Encode Area Ceiling
    ceiling = int(data.AreaCeiling) 
    ceiling = int(round((ceiling + 1000)/.5))
    ceiling= struct.pack('<H',ceiling)
    #print(ceiling.hex())
    encodedmessage[13:13+len(ceiling)] = ceiling
    #print(encodedmessage.hex())

    #Encode Area Floor
    floor = int(data.AReaFloor) 
    floor = int(round((floor + 1000)/.5))
    floor= struct.pack('<H',floor)
    #print(floor.hex())
    encodedmessage[15:15+len(floor)] = floor
    #print(encodedmessage.hex())
    
    #Encode UA Classification
    if data.ClassificationType == 1:
        #[4 bits, Category][4bits, Class]
        classification = concat_nybble(int(data.CategoryEU), int(data.ClassEU))
    else: classification = 0
    #print(format(classification,'02x'))
    encodedmessage[17] = classification
    #print(encodedmessage.hex())
    
    #Encode Operator Altitude 
    altitude = int(data.OperatorAltitudeGeo) 
    altitude = int(round((altitude + 1000)/.5))
    altitude= struct.pack('<H',altitude)
    #print(altitude.hex())
    encodedmessage[18:18+len(altitude)] = altitude
    #print(encodedmessage.hex())

    #Encode Timestamp
    timestamp = unix_timestamp_since_2019()
    #print(timestamp.hex())
    encodedmessage[20:20+len(timestamp)] = timestamp
    
    #Last byte reserved
    if args.verbose:
        print(f'System:            {encodedmessage.hex()}')

    return encodedmessage

def encodeOperator (data: Operator):
    '''Encodes Operator ID data into a byte payload for transmission via wifi beacon'''
    #Initialize message buffer
    encodedmessage = bytearray(25)
    #print(encodedmessage.hex())

    #Operator ID header [4bits, Message Type][4bits, Protocol Version]
    Header = concat_nybble(int(ODID.ODID_messagetype.OPERATOR_ID), PROTOCOL_VER)
    encodedmessage[0] = Header

    #Encode Operator ID Type
    operatorIDtype = int(data.OperatorIDType)
    #print(format(operatorIDtype,'02x'))
    encodedmessage[1] = operatorIDtype
    #print(encodedmessage.hex())

    #Encode Operator ID
    operatorID = data.OperatorID
    operatorID = operatorID.encode('utf-8')
    #print(operatorID.hex())
    encodedmessage[2:2+len(operatorID)] = operatorID

    if args.verbose:
        print(f'Operator:          {encodedmessage.hex()}')

    #Last Bytes reserved
    return encodedmessage

def encodeAuth (data: Auth):
    '''Encodes Authentication data into a byte payload for transmission via wifi beacon'''
    #Initialize message buffer
    encodedmessage = bytearray(25)
    #print(encodedmessage.hex()) 

    #Authentication header [4bits, Message Type][4bits, Protocol Version]
    Header = concat_nybble(int(ODID.ODID_messagetype.AUTH), PROTOCOL_VER)
    encodedmessage[0] = Header

    #Encode Auth Type, Page Number [4 bits, Auth Type][4 bits, Data Page number]
    type_page = concat_nybble(int(data.AuthType), int(data.DataPage))
    encodedmessage[1] = type_page
    #print(format(type_page,'02x'))

    #Page 0 
    if data.DataPage == 0:
        #Encode Last Page Index [4 bits, reserver][4 bits, last page]
        index = concat_nybble(0,int(data.LastPageIndex))
        encodedmessage[2] = index
        #print(format(index,'02x'))

        #Encode Length
        length = int(data.Length)
        encodedmessage[3] = length
        #print(format(length,'02x'))

        #Encode Timestamp
        auth_time = unix_timestamp_since_2019()
        encodedmessage[4:4+len(auth_time)] = auth_time
        #print(auth_time.hex())

        #Encode Authentication Data
        auth_data = data.AuthData
        #print(auth_data.hex())
        encodedmessage[8:8+len(data.AuthData)] = auth_data


    else:
        auth_data = data.AuthData
        #print(auth_data.hex())
        encodedmessage[2:2+len(data.AuthData)] = auth_data

    if args.verbose:
        print(f'Auth{data.DataPage}:             {encodedmessage.hex()}') 

    return encodedmessage

def encodeMsgPack (basicID_enc, locationID_enc, Auth0_enc, Auth1_enc, Auth2_enc, Auth3_enc, system_enc, operator_enc):
    '''Encodes a Message Pack into a byte payload for transmission via wifi beacon'''
    #Initialize message buffer
    encodedmessage = bytearray((25*8)+3)
    #print(encodedmessage.hex()) 

    #Message Pack header [4bits, Message Type][4bits, Protocol Version]
    Header = concat_nybble(int(ODID.ODID_messagetype.PACKED), PROTOCOL_VER)
    encodedmessage[0] = Header

    #Encode Message Size
    size = MESSAGE_SIZE
    encodedmessage[1] = size
    #print(format(size,'02x'))

    #Encode number of msgs in pack
    msgs = 8
    encodedmessage[2] = msgs
    #print(format(msgs,'02x'))

    #Encode Messages
    data = basicID_enc + locationID_enc + Auth0_enc + Auth1_enc + Auth2_enc + Auth3_enc + system_enc + operator_enc
    encodedmessage[3:3+len(data)] = data

    if args.verbose:
        print(f"Message Pack:      {data.hex()[0:50]}")
        for i in range(50, len(data.hex()), 50):
            print(f"                   {data.hex()[i:i+50]}")

    return encodedmessage

# Function to create and send beacon frames with dynamic payload
def send_beacon(interface, ssid, bssid, payload, interval, send_udp=False, ip = None, port=None):

    counter = interval%256
    counter_bytes = counter.to_bytes(1, 'big')  # 1-byte counter (0x0000 - 0xFFFF) per OpenDroneID spec

    if not isinstance(payload, bytearray):
        raise ValueError("Payload must be a byte array")

    # Construct beacon frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS+privacy")
        
    # SSID IE
    essid_ie = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        
    # Vendor Specific IE (custom payload as bytes)
    vendor_ie = Dot11Elt(ID=221, info=b'\xFA\x0B\xBC\x0D' + counter_bytes + payload)  #  OUI: FA-0B-BC, Type: 0x0D per ASTM F3411-22a
        
    # Construct full frame
    frame = RadioTap()/dot11/beacon/essid_ie/vendor_ie
        
    # Send the beacon
    sendp(frame, iface=interface, verbose=False)
    tx_time = time.time()

    # Optional: Send via UDP broadcast
    if send_udp:
        if port is None:
            raise ValueError("udp_port must be specified when send_udp is True")
        udp_payload = b'\xFA\x0B\xBC\x0D' + counter_bytes + payload
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(udp_payload, (ip, port))
        udp_socket.close()
    
    print(f"[{tx_time:.6f}] Sent beacon for interval {interval} | "
          f"SSID: {ssid} | OUI: FA-0B-BC | Type: 0x0D | Counter: 0x{counter:02X} | Payload: {payload.hex()}")
    
    return tx_time

def parse_basic_id(msg) -> BasicID:
    """
    Parse a MAVLink OPEN_DRONE_ID_BASIC_ID message into a BasicID dataclass.
    """
    return BasicID(
        UAtype=msg.ua_type,
        IDtype=msg.id_type, 
        UASID=bytes(msg.uas_id).decode('utf-8').rstrip('\x00')
        )

def parse_location_msg(msg) -> Location:
    return Location(
        status=msg.status,
        direction=msg.direction,
        SpeedHorizontal=msg.speed_horizontal,
        SpeedVertical=msg.speed_vertical,
        Latitude=msg.latitude,
        Longitude=msg.longitude,
        AltitudeBaro=msg.altitude_barometric,
        AltitudeGeo=msg.altitude_geodetic,
        HeightType=msg.height_reference,
        Height=msg.height,
        HorizAccuracy=msg.horizontal_accuracy,
        VertAccuracy=msg.vertical_accuracy,
        BaroAccuracy=msg.barometer_accuracy,
        SpeedAccuracy=msg.speed_accuracy,
        TSAccuracy=msg.timestamp_accuracy,
        TimeStamp=msg.timestamp
    )



def parse_system(msg) -> System:
    """Parse an OPEN_DRONE_ID_SYSTEM MAVLink message into a System dataclass."""
    return System(
        LocationType = msg.operator_location_type,
        ClassificationType = msg.classification_type,
        OperatorLatitude = msg.operator_latitude / 1e7,  # usually in degrees * 1e7
        OperatorLongitude = msg.operator_longitude / 1e7,
        AreaCount = msg.area_count,
        AreaRadius = msg.area_radius,
        AreaCeiling = msg.area_ceiling,
        AReaFloor = msg.area_floor,
        ClassEU = msg.class_eu,
        CategoryEU = msg.category_eu,
        OperatorAltitudeGeo = msg.operator_altitude_geo,
        Timestamp = msg.timestamp
    )

def parse_operator(msg) -> Operator:
    """Parse an OPEN_DRONE_ID_OPERATOR_ID MAVLink message into a Operator dataclass."""
    return Operator(
        OperatorIDType = msg.operator_id_type,
        OperatorID = msg.operator_id.rstrip('\x00')

    )

def generate_rand_key():
    random_bytes = secrets.token_bytes(32)
    return random_bytes

def generate_interval_keys(start_key, num_keys):
    
    keys = [] # Generate list to hold keys
    keys.append(start_key)

    for i in range(num_keys):
        data = keys[i]
        hash_key = hashlib.sha256(data).digest()
        keys.append(hash_key)

    key_commit = hashlib.sha256(keys[num_keys]).digest()

    return keys[1:num_keys+1], key_commit

def save_keys_to_file(keys, filename):
    with open(filename, "w") as file:
        for key in keys:
            file.write(key.hex() + "\n")

def send_mission_data(ip, port,operator_id, uas_id, start_time, key, end_time=0):
    # Prepare our context
    context = zmq.Context()

    # Create the mission update message
    mission_data = messages_pb2.MissionUpdate()
    mission_data.Operator_ID = operator_id
    mission_data.UAS_ID = uas_id
    mission_data.Start = start_time
    mission_data.End = end_time
    mission_data.KeyCommit = key

    # Create the sending sockt to send data 
    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(ip, port))

    # Send request data message
    print("Sending data request\n")
    client.send(b'MISSION_UPDATE',flags=zmq.SNDMORE)
    client.send(mission_data.SerializeToString())

    # Wait for response
    message = client.recv_multipart()
    print("Data received from USS\n")

    if message[0] == b'REPLY_DATA':
        data_reply = messages_pb2.ReplyData()
        data_reply.ParseFromString(message[1])
        if data_reply.KeyCommit == key:
            print('Database updated successfully')
        else:
            print('Updated key committment does not match')
            print(data_reply.KeyCommit)
    elif message[0] == b'ERROR':
        data_reply = messages_pb2.SendError()
        print('Error code from server, database update unsuccessfull')
        print(data_reply.ErrorCode)
    else:
        print('Unrecognized message from server, database update unsuccessfull')
    
    client.close()

#Static simulated data for testing wihtout mavlink connection, i.e. poluate message class with data
basic_id = BasicID()
basic_id.UAtype = ODID.ODID_uatype.ODID_UATYPE_HELICOPTER_OR_MULTIROTOR
basic_id.IDtype = ODID.ODID_idtype.ODID_IDTYPE_CAA_REGISTRATION_ID
basic_id.UASID = "N.FA12345678"

location = Location()
location.status = ODID.ODID_status.ODID_STATUS_AIRBORNE
location.direction = 70
location.HeightType = ODID.ODID_Height_reference.ODID_HEIGHT_REF_OVER_GROUND
location.SpeedHorizontal = 63
location.SpeedVertical = -13
location.Latitude = 42.3449919
location.Longitude = -71.0827252
location.AltitudeBaro = 500
location.AltitudeGeo = 750
location.Height = 250
location.VertAccuracy = ODID.ODID_Vertical_accuracy.ODID_VER_ACC_1_METER
location.HorizAccuracy = ODID.ODID_Horizontal_accuracy.ODID_HOR_ACC_1NM
location.BaroAccuracy = ODID.ODID_Vertical_accuracy.ODID_VER_ACC_1_METER
location.SpeedAccuracy = ODID.ODID_Speed_Accuracy.ODID_SPEED_ACC_1_METERS_PER_SECOND
location.TSAccuracy = ODID.ODID_Timestamp_accuracy.ODID_TIME_ACC_0_6_SECOND

system = System()
system.LocationType = ODID.ODID_operator_location_type.ODID_OPERATOR_LOCATION_TYPE_FIXED
system.ClassificationType = ODID.ODID_classification_type.ODID_CLASSIFICATION_TYPE_EU
system.OperatorLatitude = 42.3449919
system.OperatorLongitude = -71.0827252
system.AreaCount = 64000
system.AreaRadius = 1.2
system.AreaCeiling = 500
system.AReaFloor = 200
system.CategoryEU = ODID.ODID_category_EU.ODID_CATEGORY_EU_SPECIFIC
system.ClassEU = ODID.ODID_class_EU.ODID_CLASS_EU_CLASS_3
system.OperatorAltitudeGeo = 750

operator = Operator()
operator.OperatorIDType = ODID.ODID_operatorIdType.ODID_OPERATOR_ID
operator.OperatorID = "TBRDOPERATOR"

# === MAVLink Listener Thread ===
def mavlink_listener():
    while True:
        try:
            msg = mav_connection.recv_match(blocking=True, timeout=5)
            if msg is None:
                continue

            msg_type = msg.get_type()
            with buffer_lock:
                if msg_type == 'OPEN_DRONE_ID_BASIC_ID':
                    latest_messages['BASIC_ID'] = parse_basic_id(msg)
                elif msg_type == 'OPEN_DRONE_ID_LOCATION':
                    latest_messages['LOCATION'] = parse_location_msg(msg)
                elif msg_type == 'OPEN_DRONE_ID_SYSTEM':
                    latest_messages['SYSTEM'] = parse_system(msg)
                elif msg_type == 'OPEN_DRONE_ID_OPERATOR_ID':
                    latest_messages['OPERATOR'] = parse_operator(msg)
        except Exception as e:
            print(f"[MAVLink Listener] Error: {e}")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="TBRD transmitter application")
    parser.add_argument("-s","--static",action='store_true',help="Use static data instead of a mavlink connection")
    parser.add_argument("-v","--verbose",action='store_true',help="Verbose output for debugging")
    parser.add_argument("-u","--udp",action='store_true',help="Broadcast TBRD over UDP")
    parser.add_argument('-c','--config', type=str, default='tx_config.ini', help="Config filepath")

    args = parser.parse_args()

    #Load config
    config = ConfigParser()
    try:
        config.read(args.config)
    except:
        print("Unable to load config file")
    
    #TODO: Add some config error checking

    #Load config values
    uss_ip = config['USS']['ip']
    uss_port = int(config['USS']['port'])
    interface = config['Tx']['interface']
    ssid = config['Tx']['ssid']
    bssid = config['Tx']['bssid']
    operator.OperatorID = config['Mission']['operator_id']  
    basic_id.UASID = config['Mission']['uas_id']
    udp_ip = config['Tx']['udp_ip']
    udp_port = config['Tx']['udp_port']

    #load keys from file if provided, otherwise generate keys
    if config['OPTIONAL']['key_file']:
        keyfile = config['OPTIONAL']['key_file']
        keys = load_keys_from_file(keyfile)
        NUM_KEYS = len(keys)
        if config['OPTIONAL']['key_commit']:
            key_commit = config['OPTIONAL']['key_commit']
        else:
            print("Warning, no key committment value provided!!!\n")
    else:
        key_seed = generate_rand_key() #super secret, would normally stay in TEE
        keys, key_commit = generate_interval_keys(key_seed, NUM_KEYS)
        save_keys_to_file(keys,KEY_OUTPUT_FILE)

    interval = 1 # initialize interval            
    i = NUM_KEYS - 1 #Start key index

    #Connect to SITL simulator 
    if not args.static:
        mav_connection = mavutil.mavlink_connection('udpin:127.0.0.1:14555')
        mav_connection.wait_heartbeat()
        print("Heartbeat from system (system %u component %u)" % (mav_connection.target_system, mav_connection.target_component))
        listener_thread = threading.Thread(target=mavlink_listener, daemon=True)
        listener_thread.start()

#Start loop here
    while True:

        #Process mavlink messages if using dynamic data
        if not args.static:
            with buffer_lock:
                basic_id_data = latest_messages.get('BASIC_ID')
                location_data = latest_messages.get('LOCATION')
                system_data = latest_messages.get('SYSTEM')
                operator_data = latest_messages.get('OPERATOR')
        else:
            # Load or generate static data here if desired
            pass
    
        if args.verbose:
            print(f'Starting interval {interval}...\n')

        #Create payload for input tp HMAC
        #Get Encoded messages for TBRD authenticated payload
        basicid_msg = encodeBasicID(basic_id)
        location_msg = encodeLocation(location)
        system_msg = encodeSystem(system)
        operator_msg = encodeOperator(operator)

        #Interval Key used for HMAC
        if args.verbose:
            print(f'Interval Key:      {keys[i].hex()}')

        #Generate HMAC
        tbrd_payload = interval.to_bytes(4, 'big') + basicid_msg + location_msg + system_msg + operator_msg

        #Derive interval key
        key_prime = hashlib.sha512(keys[i]).hexdigest()
        key_prime = bytes(key_prime[:64],'utf-8')

        #Generate HMAC of tbrd payload
        tbrd_hmac = hmac.new(key_prime,tbrd_payload,hashlib.sha256).digest()
        
        if args.verbose:
            print(f'Auth Payload:     {tbrd_payload.hex()}')
            print(f'Auth Payload HMAC: {tbrd_hmac.hex()}')

        if args.verbose:
            print(f'Key Disclosure:    {keys[(i+1)%NUM_KEYS].hex()}')
        #Create TBRD auth mesage
        tbrd_auth_msg = interval.to_bytes(4, 'big') + tbrd_hmac + keys[(i+1)%NUM_KEYS]
        if args.verbose:
            print(f'Auth MSG:          {tbrd_auth_msg.hex()}')

        #Split TBRD message into 4 auth messages
        auth0 = Auth()
        auth0.AuthType = ODID.ODID_authtype.ODID_AUTH_SPECIFIC_AUTHENTICATION
        auth0.DataPage = 0
        auth0.LastPageIndex = 3
        auth0.Length = 64
        auth0.AuthData = tbrd_auth_msg[:17]
        auth0_msg = encodeAuth(auth0)
    
        auth1 = Auth()
        auth1.AuthType = ODID.ODID_authtype.ODID_AUTH_SPECIFIC_AUTHENTICATION
        auth1.DataPage = 1
        auth1.AuthData = tbrd_auth_msg[17:40]
        auth1_msg = encodeAuth(auth1)

        auth2 = Auth()
        auth2.AuthType = ODID.ODID_authtype.ODID_AUTH_SPECIFIC_AUTHENTICATION
        auth2.DataPage = 2
        auth2.AuthData = tbrd_auth_msg[40:63]
        auth2_msg = encodeAuth(auth2)

        auth3 = Auth()
        auth3.AuthType = ODID.ODID_authtype.ODID_AUTH_SPECIFIC_AUTHENTICATION
        auth3.DataPage = 3
        auth3.AuthData = tbrd_auth_msg[63:68]
        auth3_msg = encodeAuth(auth3)

        #Encode Message Pack
        msg_pack = encodeMsgPack(basicid_msg, location_msg, auth0_msg, auth1_msg, auth2_msg, auth3_msg, system_msg, operator_msg)

        # Send mission to USS server at start of mission
        if interval == 1:    
            interval_start = time.time()
            #Assume first time of transmission is directly in middle of transmission interval
            #Define start/end reference times based on first transmisison
            ts = interval_start
            te = interval_start + T
            send_mission_data(uss_ip,uss_port,operator.OperatorID, basic_id.UASID, ts, key_commit.hex())

       #Determine if we are within permitted transmission time       
        now = time.time()
        
        if now < (((interval-1)*T) + ts + E):
            while now < (((interval-1)*T) + ts + E):
                time.sleep(T/10)
                now = time.time()

        if (((interval-1)*T) + ts + E) <= now <= (((interval-1)*T) + te - E):
            #Send Beacon
            if args.udp: 
                tx_time = send_beacon(interface, ssid, bssid, msg_pack, interval, send_udp=True,ip = udp_ip, port=int(udp_port))
            else: 
                tx_time = send_beacon(interface, ssid, bssid, msg_pack, interval)

        else:
            print('Dropping beacon, unable to send in permitted transmission window')
            print(interval)
            print((((interval-1)*T) + ts + E))
            print(now)
            print((((interval-1)*T) + te - E))



        # Increment counter and interval
        interval = interval + 1
        # Decrement key value
        i = (i-1)

        print('\n')

        #Stop transmitting when keys exhausted
        if i == 0:
            break
        
