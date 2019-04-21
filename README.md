# Super Survey Bot Server
An asyncronous chat server and client written in Python 3.

## Usage
- Clone the project
- Navigate to the project folder in the terminal
- If Running Server:
    - `python server.py "" -p <port_num>`
- If Running Client:
    - `python client.py <server_addr> -p <port_num>`
    - NOTE: When connecting to localhost use `-ca ca.crt` with the client call, with servers that have verified ca files this is unnecessary
