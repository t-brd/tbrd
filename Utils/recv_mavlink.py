from pymavlink import mavutil

# Change this to your actual connection string
# Example: serial ('COM3' or '/dev/ttyUSB0') or UDP ('udp:127.0.0.1:14550')
connection_string = 'udp:127.0.0.1:14555'

# Connect to the vehicle
mav = mavutil.mavlink_connection(connection_string)

print("Waiting for OpenDroneID messages...")

while True:
    msg = mav.recv_match(type=[
        "OPEN_DRONE_ID_BASIC_ID",
        "OPEN_DRONE_ID_LOCATION",
        "OPEN_DRONE_ID_SYSTEM",
        "OPEN_DRONE_ID_OPERATOR_ID",
        "OPEN_DRONE_ID_AUTHENTICATION",
        "OPEN_DRONE_ID_MESSAGE_PACK"
    ], blocking=True)

    if msg:
        print(f"\nReceived {msg.get_type()}:")
        print(msg.to_dict())