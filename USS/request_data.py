import zmq
import messages_pb2
import json
import argparse

def main ():
    # Parse Arguments
    parser = argparse.ArgumentParser(description="Testing app to request data from USS")
    parser.add_argument("--ip",help="IP address of USS")
    parser.add_argument("--port", type=int, default=5555, help="Port of USS (default: 5555)")
    parser.add_argument("--operator-id", type=str, help ="Operator ID for data request")
    parser.add_argument("--uas-id", type=str, help ="UAS ID for data request")
    parser.add_argument("--time",type=int,help="Timestamp for data request in unix epoch format")
    
    args = parser.parse_args()
    USS_IP = args.ip
    USS_PORT = args.port
    operator_id = args.operator_id
    uas_id = args.uas_id
    timestamp = args.time

    # Prepare our context
    context = zmq.Context()

    # Create the request data message
    request_data = messages_pb2.RequestData()
    request_data.Operator_ID = operator_id
    request_data.UAS_ID = uas_id
    request_data.Time = timestamp

    # Create the sending sockt to send data 
    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(USS_IP, USS_PORT))

    # Send request data message
    print("Sending data request\n")
    client.send(b'REQUEST_DATA',flags=zmq.SNDMORE)
    client.send(request_data.SerializeToString())

    # Wait for response
    message = client.recv_multipart()
    print("Data received from USS\n")
    
    # Print key commitment if valid record
    if message[0] == b'REPLY_DATA':
        data_reply = messages_pb2.ReplyData()
        data_reply.ParseFromString(message[1])
        print("Key Commitment received:\n")
        print(data_reply.KeyCommit)
        print(data_reply.Start)

    # Print response if some error
    elif message[0] == b'ERROR':
        print("Error from server\n")
        error_message = messages_pb2.SendError()
        error_message.ParseFromString(message[1])
        print(error_message.ErrorCode)
    
    else:
        print("Unknown message from server")
    
    
if __name__ == "__main__":
    main()