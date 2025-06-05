from pymavlink import mavutil

master = mavutil.mavlink_connection('udp:127.0.0.1:14555')

# Wait for a heartbeat to make sure connection is live
master.wait_heartbeat()
print("Heartbeat received from system (system %u component %u)" % (master.target_system, master.target_component))

# Continuously listen to GLOBAL_POSITION_INT messages
while True:
    msg = master.recv_match(type='OPEN_DRONE_ID_MESSAGE_PACK', blocking=True)
    if msg:
        print(f"Received Message Pack:")
        print(f" - Number of Messages: {msg.single_message_size} bytes each")
        
        # The "pack" field contains up to 8 packed messages
        for i in range(msg.n_messages):
            start = i * msg.single_message_size
            end = start + msg.single_message_size
            packed_message = msg.pack[start:end]
            print(f" -- Message {i+1}: {packed_message.hex()}")