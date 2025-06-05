from enum import IntEnum

class ODID_messagetype(IntEnum):
    BASIC_ID = 0
    LOCATION = 1
    AUTH = 2
    SELF_ID = 3
    SYSTEM = 4
    OPERATOR_ID = 5
    PACKED = 0xF
    INVALID = 0xFF

class ODID_idtype(IntEnum):
    ODID_IDTYPE_NONE = 0
    ODID_IDTYPE_SERIAL_NUMBER = 1
    ODID_IDTYPE_CAA_REGISTRATION_ID = 2 # Civil Aviation Authority
    ODID_IDTYPE_UTM_ASSIGNED_UUID = 3   # UAS (Unmanned Aircraft System) Traffic Management
    ODID_IDTYPE_SPECIFIC_SESSION_ID = 4 # The exact id type is specified by the first byte of UASID and these type
                                         # values are managed by ICAO. 0 is reserved. 1 - 224 are managed by ICAO.
                                         # 225 - 255 are available for private experimental usage only

class ODID_operatorIdType(IntEnum):
    ODID_OPERATOR_ID = 0

class ODID_operator_location_type(IntEnum):
    ODID_OPERATOR_LOCATION_TYPE_TAKEOFF = 0   # Takeoff location and altitude
    ODID_OPERATOR_LOCATION_TYPE_LIVE_GNSS = 1 # Dynamic/Live location and altitude
    ODID_OPERATOR_LOCATION_TYPE_FIXED = 2     # Fixed location and altitude

class ODID_classification_type(IntEnum):
    ODID_CLASSIFICATION_TYPE_UNDECLARED = 0
    ODID_CLASSIFICATION_TYPE_EU = 1 # European Union

class ODID_uatype(IntEnum):
    ODID_UATYPE_NONE = 0
    ODID_UATYPE_AEROPLANE = 1  # Fixed wing
    ODID_UATYPE_HELICOPTER_OR_MULTIROTOR = 2
    ODID_UATYPE_GYROPLANE = 3
    ODID_UATYPE_HYBRID_LIFT = 4 # Fixed wing aircraft that can take off vertically
    ODID_UATYPE_ORNITHOPTER = 5
    ODID_UATYPE_GLIDER = 6
    ODID_UATYPE_KITE = 7
    ODID_UATYPE_FREE_BALLOON = 8
    ODID_UATYPE_CAPTIVE_BALLOON = 9
    ODID_UATYPE_AIRSHIP = 10 # Such as a blimp
    ODID_UATYPE_FREE_FALL_PARACHUTE = 11 # Unpowered
    ODID_UATYPE_ROCKET = 12
    ODID_UATYPE_TETHERED_POWERED_AIRCRAFT = 13
    ODID_UATYPE_GROUND_OBSTACLE = 14
    ODID_UATYPE_OTHER = 15

class ODID_status(IntEnum):
    ODID_STATUS_UNDECLARED = 0
    ODID_STATUS_GROUND = 1
    ODID_STATUS_AIRBORNE = 2
    ODID_STATUS_EMERGENCY = 3
    ODID_STATUS_REMOTE_ID_SYSTEM_FAILURE = 4

class ODID_Height_reference(IntEnum):
    ODID_HEIGHT_REF_OVER_TAKEOFF = 0
    ODID_HEIGHT_REF_OVER_GROUND = 1

class ODID_Horizontal_accuracy(IntEnum):
    ODID_HOR_ACC_UNKNOWN = 0
    ODID_HOR_ACC_10NM = 1      # Nautical Miles. 18.52 km
    ODID_HOR_ACC_4NM = 2       # 7.408 km
    ODID_HOR_ACC_2NM = 3       # 3.704 km
    ODID_HOR_ACC_1NM = 4       # 1.852 km
    ODID_HOR_ACC_0_5NM = 5     # 926 m
    ODID_HOR_ACC_0_3NM = 6     # 555.6 m
    ODID_HOR_ACC_0_1NM = 7     # 185.2 m
    ODID_HOR_ACC_0_05NM = 8    # 92.6 m
    ODID_HOR_ACC_30_METER = 9
    ODID_HOR_ACC_10_METER = 10
    ODID_HOR_ACC_3_METER = 11
    ODID_HOR_ACC_1_METER = 12
    # 13 to 15 reserved
    
class ODID_Vertical_accuracy(IntEnum):
    ODID_VER_ACC_UNKNOWN = 0
    ODID_VER_ACC_150_METER = 1
    ODID_VER_ACC_45_METER = 2
    ODID_VER_ACC_25_METER = 3
    ODID_VER_ACC_10_METER = 4
    ODID_VER_ACC_3_METER = 5
    ODID_VER_ACC_1_METER = 6
    # 7 to 15 reserved

class ODID_Speed_Accuracy(IntEnum):
    ODID_SPEED_ACC_UNKNOWN = 0
    ODID_SPEED_ACC_10_METERS_PER_SECOND = 1
    ODID_SPEED_ACC_3_METERS_PER_SECOND = 2
    ODID_SPEED_ACC_1_METERS_PER_SECOND = 3
    ODID_SPEED_ACC_0_3_METERS_PER_SECOND = 4
    # 5 to 15 reserved

class ODID_Timestamp_accuracy(IntEnum):
    ODID_TIME_ACC_UNKNOWN = 0
    ODID_TIME_ACC_0_1_SECOND = 1
    ODID_TIME_ACC_0_2_SECOND = 2
    ODID_TIME_ACC_0_3_SECOND = 3
    ODID_TIME_ACC_0_4_SECOND = 4
    ODID_TIME_ACC_0_5_SECOND = 5
    ODID_TIME_ACC_0_6_SECOND = 6
    ODID_TIME_ACC_0_7_SECOND = 7
    ODID_TIME_ACC_0_8_SECOND = 8
    ODID_TIME_ACC_0_9_SECOND = 9
    ODID_TIME_ACC_1_0_SECOND = 10
    ODID_TIME_ACC_1_1_SECOND = 11
    ODID_TIME_ACC_1_2_SECOND = 12
    ODID_TIME_ACC_1_3_SECOND = 13
    ODID_TIME_ACC_1_4_SECOND = 14
    ODID_TIME_ACC_1_5_SECOND = 15

class ODID_authtype(IntEnum):
    ODID_AUTH_NONE = 0
    ODID_AUTH_UAS_ID_SIGNATURE = 1
    ODID_AUTH_OPERATOR_ID_SIGNATURE = 2
    ODID_AUTH_MESSAGE_SET_SIGNATURE = 3
    ODID_AUTH_NETWORK_REMOTE_ID = 4
    ODID_AUTH_SPECIFIC_AUTHENTICATION = 5

class ODID_category_EU(IntEnum):
    ODID_CATEGORY_EU_UNDECLARED = 0
    ODID_CATEGORY_EU_OPEN = 1
    ODID_CATEGORY_EU_SPECIFIC = 2
    ODID_CATEGORY_EU_CERTIFIED = 3

class ODID_class_EU(IntEnum):
    ODID_CLASS_EU_UNDECLARED = 0
    ODID_CLASS_EU_CLASS_0 = 1
    ODID_CLASS_EU_CLASS_1 = 2
    ODID_CLASS_EU_CLASS_2 = 3
    ODID_CLASS_EU_CLASS_3 = 4
    ODID_CLASS_EU_CLASS_4 = 5
    ODID_CLASS_EU_CLASS_5 = 6
    ODID_CLASS_EU_CLASS_6 = 7 