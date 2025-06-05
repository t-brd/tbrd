import zmq
import messages_pb2
import json
import argparse

def main ():
    # Parse Arguments
    parser = argparse.ArgumentParser(description="Testing app to report mission to USS")
    parser.add_argument("--ip",help="IP address of USS")
    parser.add_argument("--port", type=int, default=5555, help="Port of USS (default: 5555)")
    parser.add_argument("--operator-id", type=str, help ="Operator ID for mission")
    parser.add_argument("--uas-id", type=str, help ="UAS ID for mission")
    parser.add_argument("--start-time",type=int,help="Start time for mission in unix epoch format")
    parser.add_argument("--end-time",type=int,help="Start time for mission in unix epoch format")
    parser.add_argument("--key-commitment",type=str, help="Mission key commitment")
    
    args = parser.parse_args()
    USS_IP = args.ip
    USS_PORT = args.port
    operator_id = args.operator_id
    uas_id = args.uas_id
    start_time = args.start_time
    end_time = args.end_time
    key = args.key_commitment

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
    client.connect("tcp://%s:%s" %(USS_IP, USS_PORT))

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
    elif message[0] == b'ERROR':
        print('Error code from server, database update unsuccessfull')
    else:
        print('Unrecognized message from server, database update unsuccessfull')

    
if __name__ == "__main__":
    main()