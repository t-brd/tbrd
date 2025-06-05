import socket

def send_query(operator_id, uas_id, timestamp):

    host = '34.56.6.89' 
    port = 8081          
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    request = f"/query?operator_id={operator_id}&uas_id={uas_id}&timestamp={timestamp}\r\n\r\n"
    client.send(request.encode('utf-8'))
    response = client.recv(1024).decode('utf-8')
    print(f"{response}")
    client.close()

# Query
operator_id = 'TBRDOPERATOR'
uas_id = 'N.FA12345678'
timestamp = '2025-01-01T00:00:00Z'
send_query(operator_id, uas_id, timestamp)