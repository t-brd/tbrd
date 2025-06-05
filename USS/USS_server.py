
import zmq
import argparse
import messages_pb2
import sys
import json


# JSON data format of database
# {
#   "Operators": [
#     {
#       "Operator_ID": "OP12345",
#       "Missions": [
#         { 
#            "UAS_ID":"XXXX",
#            "Start":XXXXX, 
#            "End":XXXXX, 
#            "Key_Commit":XXXXXX}
#         },
#         { 
#            "UAS_ID":"XXXX",
#            "Start":XXXXX, 
#            "End":XXXXX, 
#            "Key_Commit":XXXXXX}
#         },
#       ]
#     },
#     {
#       "Operator_ID": "OP12345",
#       "Missions": [
#         { 
#            "UAS_ID":"XXXX",
#            "Start":XXXXX, 
#            "End":XXXXX, 
#            "Key_Commit":XXXXXX}
#         }
#       ]
#     }
#   ]
# }

database = {}

#Parse Arguments
parser = argparse.ArgumentParser(description="USS server for TBRD proof of concept")
parser.add_argument("--ip", default="0.0.0.0", help="IP address to bind to (default: 0.0.0.0)")
parser.add_argument("--port", type=int, default=5555, help="Port to bind to (default: 5555)")
args = parser.parse_args()
USS_PORT = args.port
USS_IP = args.ip

#  Prepare our context and sockets
context = zmq.Context()

# Bind server socket, we are using REQ-REP pattern
server = context.socket(zmq.REP)
bind_address = f"tcp://{USS_IP}:{USS_PORT}" 
server.bind(bind_address)

def handle_mission_update(message):
    '''Handle a report mission message'''
    mission_update = messages_pb2.MissionUpdate()
    mission_update.ParseFromString(message[1])

    operator_id = mission_update.Operator_ID 
    uas_id = mission_update.UAS_ID  
    start_time = mission_update.Start
    end_time = mission_update.End  
    key = mission_update.KeyCommit 

    print("Processing mission update request for:\n")
    print(operator_id)
    print(uas_id)
    print(start_time)
    print(end_time)
    print(key)
    print("\n")

    #Check to see if mission update already exists
    key_commit = get_key_commit(operator_id,uas_id,start_time)

    if key_commit: #Key commit already exists for this time frame, return error code 3        
            print("Key commitment already exists for this time period, sending error code 3")
            reply = messages_pb2.SendError()
            reply.ErrorCode = 3
            server.send(b'ERROR',flags=zmq.SNDMORE)
            server.send(reply.SerializeToString())  
            return
    
    #Update database
    print("Updating database")
    update_database(operator_id, uas_id, start_time, end_time,key)

    #send confirmation to operator
    print("Database updated, sending confirmation")
    reply = messages_pb2.ReplyData()
    reply.KeyCommit = key
    server.send(b'REPLY_DATA',flags=zmq.SNDMORE)
    server.send(reply.SerializeToString())
    return

def handle_request_data(message):
    '''Handle a request data message'''
    request_data = messages_pb2.RequestData()
    request_data.ParseFromString(message[1])

    operator_id = request_data.Operator_ID
    uas_id= request_data.UAS_ID
    timestamp = request_data.Time

    print("Processing data request for:\n")
    print(operator_id)
    print(uas_id)
    print(timestamp)
    print("\n")

    try:
        key_commit = get_key_commit(operator_id,uas_id,timestamp)
        if key_commit: #Send Key commitment if valid query
            print("Data found sending key comittment")
            reply = messages_pb2.ReplyData()
            reply.KeyCommit = key_commit[0]
            reply.Start = key_commit[1]
            server.send(b'REPLY_DATA',flags=zmq.SNDMORE)
            server.send(reply.SerializeToString())

        else: #Send error message back to requester, error code 1 for no matching record
            print("Data not found, sending error code 1")
            reply = messages_pb2.SendError()
            reply.ErrorCode = 1
            server.send(b'ERROR',flags=zmq.SNDMORE)
            server.send(reply.SerializeToString())  

    except Exception as e: #Send error message back to requester, error code 2 for lookup error
        print(f"Error retreiving key_commitment, sending error code 2: {e}")
        reply = messages_pb2.SendError()
        reply.ErrorCode = 2
        server.send(b'ERROR',flags=zmq.SNDMORE)
        server.send(reply.SerializeToString()) 
    

def get_key_commit(operator_id, uas_id, timestamp):

    for operator in database.get("Operators", []):
        if operator.get("Operator_ID") == operator_id:
            for mission in operator.get("Missions", []):
                if (mission.get("UAS_ID") == uas_id and
                    mission.get("Start") <= timestamp):
                    if mission.get("End") == 0:
                        return [mission.get("Key_Commit"), mission.get("Start")]
                    else:
                        if mission.get("End") >= timestamp:
                            return [mission.get("Key_Commit"), mission.get("Start")]
                            
    return None

def update_database(operator_id, uas_id, start_time, end_time,key):

    if "Operators" not in database:
        database["Operators"] = []

    new_mission = {
        "UAS_ID": uas_id,
        "Start": start_time,
        "End": end_time,
        "Key_Commit": key
    }    
    
    # Check if the operator exists
    for operator in database.get("Operators", []):
        if operator.get("Operator_ID") == operator_id:
            operator["Missions"].append(new_mission)
            return  # Done updating

    # If operator not found, create a new on
    new_operator = {
        "Operator_ID": operator_id,
        "Missions": [new_mission]
    }
    database["Operators"].append(new_operator)

def main(database):

    print(f"[Server] Listening on {bind_address}...")

    # Main loop waiting for users messages
    poll = zmq.Poller()
    poll.register(server, zmq.POLLIN)
    poll.register(sys.stdin, zmq.POLLIN)


    while True:
        sock = dict(poll.poll())
        if server in sock and sock[server] == zmq.POLLIN:
            message = server.recv_multipart()

            if message[0]== b'MISSION_UPDATE':
                print("Received [%s] message" % message[0])
                handle_mission_update(message)
            elif message[0] == b'REQUEST_DATA':
                print("Received [%s] message" % message[0])
                handle_request_data(message)
            else:
                print("Received [%s] message" % message[0])
                print('Dropping unknown message')
        elif sys.stdin.fileno() in sock and sock[0] == zmq.POLLIN:
            userin = sys.stdin.readline().splitlines()[0]
            # get the first work on user input
            cmd = userin.split(' ', 2)

            # if it's list send "LIST", note that we should have used google protobuf
            if cmd[0] == 'LIST':
                pretty_database = json.dumps(database,indent = 4)
                print(pretty_database)
            if cmd[0] == 'CLEAR':
                database = {}

if __name__ == "__main__":
    main(database)