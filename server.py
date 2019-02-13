#!/usr/bin/env python3
# Foundations of Python Network Programming, Third Edition
# https://github.com/brandon-rhodes/fopnp/blob/m/py3/chapter07/srv_asyncio2.py
# Asynchronous I/O inside an "asyncio" coroutine.

# Last modified by Alice Easter && Eric Cacciavillani on 4/26/18
# Last modified as Super-Survey-Bot-Server by Alice Easter on 02/10/19
import json

import argparse
import asyncio
import ssl
import struct
import shelve


class AsyncServer(asyncio.Protocol):
    transport_map = {}  # Map of user_id's to transports
    all_users_ever_logged = set()  # Init a set of all users ever logged into the server

    def __init__(self):
        super().__init__()
        self.user_id = None
        self.device_type = None

        # Establish the user associated with this object
        self.thread_transport = None

        '''
        Since we need to send message to individual user, we have a modifiable
        current transport that we can use to determine the recipient of any
        given message
        '''
        self.current_transport = None
        self.__buffer = ""
        self.data_len = 0

        # Pull data from db upon client init
        self.db = shelve.open('data/client_lists')

        try:
            AsyncServer.all_users_ever_logged = self.db["all_users"]

        except KeyError:
            self.db["all_users"] = set()

        if AsyncServer.all_users_ever_logged is None:
            AsyncServer.all_users_ever_logged = set()

    def connection_made(self, transport):
        self.thread_transport = transport
        self.current_transport = transport

    # Pre: current transport should be set to the proper audience and data is
    #       already in json format and encoded to ascii
    # Post: sends data to the current transport
    # Purpose: packs the size of the data, prepends said size to the data, then
    #       sends the message through the current transport
    def send_message(self, data):
        msg = b''
        msg += struct.pack("!I", len(data))
        msg += data
        self.current_transport.write(msg)

    # Sends data to intended audience with the
    # qualifier that said audience exists
    def broadcast(self, audience, data):
        if audience in AsyncServer.transport_map[self.user_id]:
            self.current_transport = AsyncServer.transport_map[self.user_id][audience]
            data = json.dumps(data).encode('ascii')
            self.send_message(data)

    # Handles all data received from client
    def data_received(self, data):
        if self.__buffer == '':
            # Find first brace and offset the data by that
            brace_index = data.find(b'{')
            self.data_len = struct.unpack("!I", data[0:brace_index])[0]
            data = data[brace_index:(self.data_len + brace_index)]
        data = data.decode('ascii')
        self.__buffer += data

        if len(self.__buffer) == self.data_len:
            data = json.loads(self.__buffer)
            self.__buffer = ""
            self.data_len = 0

            # We have two types of accepted keys, usernames and messages
            # If we receive anything else we want to recognize it so we
            # Output it to the server console, otherwise we direct the data
            # To the proper management function
            if "DATA_TYPE" in data:
                if data["DATA_TYPE"] == "USER_ID":
                    self.validate_user(data)

                elif data["DATA_TYPE"] == "QUESTION_REQUEST":
                    self.request_question()

                elif data["DATA_TYPE"] == "QUESTION_DATA":
                    self.forward_question(data)

                elif data["DATA_TYPE"] == "ANSWER_DATA":
                    self.answer_question(data)

                elif data["DATA_TYPE"] == "BACKUP_DATA":
                    self.backup_data(data)

                else:
                    print("New message type!!! " + data["DATA_TYPE"] + ": " + data)

    # Pre: Takes in a username
    # Post: Returns username accepted status, and optionally updates user with
    #       Past messages
    # Purpose: Determines if the username is currently in use, if it is then
    #       we notify the client, if not we add them to the class's static
    #       transports variable notify them that they are logged in,  send them
    #       all previous message data, and notify other users that the new user
    #       has joined the server
    def validate_user(self, data):
        user_accept = {
            "DATA_TYPE": "LOGIN_DATA",
            "USER_ID_VALID": False,
            "LOGIN_SUCCESSFUL": False,
            "COMPANION_ACTIVE": False
        }

        self.device_type = data["DEVICE_TYPE"]
        companion = "DESKTOP" if self.device_type == "MOBILE" else "MOBILE"

        if data["USER_ID"] in AsyncServer.all_users_ever_logged or \
                self.device_type == "DESKTOP":

            user_accept["USER_ID_VALID"] = True

            # If no user active with id and device type
            # User accepted
            if data["USER_ID"] not in AsyncServer.transport_map:
                AsyncServer.transport_map[data["USER_ID"]] = {}
                AsyncServer.transport_map[data["USER_ID"]][self.device_type] = self.thread_transport
                AsyncServer.transport_map[data["USER_ID"]][companion] = None

                user_accept["LOGIN_SUCCESSFUL"] = True

            # User id active on different device type
            elif self.device_type not in AsyncServer.transport_map[data["USER_ID"]]:
                # Add current transport to map
                AsyncServer.transport_map[data["USER_ID"]][self.device_type] = self.thread_transport

                user_accept["LOGIN_SUCCESSFUL"] = True
                user_accept["COMPANION_ACTIVE"] = True

        if user_accept["LOGIN_SUCCESSFUL"]:
            # Set user id
            self.user_id = data["USER_ID"]

            # Make sure user id in all users ever logged
            AsyncServer.all_users_ever_logged.add(self.user_id)

        msg = json.dumps(user_accept).encode('ascii')
        self.send_message(msg)

    # Get's question from desktop client and sends it to mobile
    def request_question(self):
        # Create request packet
        request = {
            "DATA_TYPE": "QUESTION_REQUEST"
        }

        # Set current transport to desktop
        self.current_transport = AsyncServer.transport_map[self.user_id]["DESKTOP"]

        # Send request
        self.broadcast("DESKTOP", request)

    # Determines if companion is active and forwards question data
    def forward_question(self, data):
        if self.has_companion():
            self.current_transport = AsyncServer.transport_map[self.user_id]["MOBILE"]

            self.broadcast("MOBILE", data)

    # Takes answer data, forwards it to desktop, and stores it as needed
    def answer_question(self, data):
        if self.has_companion():
            self.current_transport = AsyncServer.transport_map[self.user_id]["DESKTOP"]

            self.broadcast("DESKTOP", data)

    # TODO: Backup data to server
    def backup_data(self, data):
        pass

    # Check for companion application
    def has_companion(self):
        if self.device_type == "DESKTOP":
            return "MOBILE" in AsyncServer.transport_map[self.user_id] \
                and AsyncServer.transport_map[self.user_id]["MOBILE"] is not None

        elif self.device_type == "MOBILE":
            return "DESKTOP" in AsyncServer.transport_map[self.user_id] \
                and AsyncServer.transport_map[self.user_id]["DESKTOP"] is not None

        else: return False

    # Remove client from the transport list upon connection lost and backup
    # data to the db
    def connection_lost(self, exc):
        # Check to make sure that the user is logged in
        if self.user_id is not None and self.user_id != '':
            if self.has_companion():
                # Establish companion type
                if self.device_type == "DESKTOP":
                    companion = "MOBILE"

                else:  # self.device_type == "MOBILE"
                    companion = "DESKTOP"

                # Create notification for mobile
                msg = {"DATA_TYPE": "COMPANION_LEFT"}

                # Set current transport to mobile companion
                self.current_transport = AsyncServer.transport_map[self.user_id][companion]

                # Send notification to mobile
                self.broadcast(companion, msg)

                # Remove desktop transport from map
                AsyncServer.transport_map[self.user_id][self.device_type] = None

            else:
                # Free up space from transport map
                AsyncServer.transport_map.pop(self.user_id)

            self.db["all_users"] = AsyncServer.all_users_ever_logged

            self.db.close()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    coro = loop.create_server(AsyncServer, *("", 9000))

    # SSL Version
    # purpose = ssl.Purpose.CLIENT_AUTH
    # context = ssl.create_default_context(purpose, cafile='ca.crt')
    # context.load_cert_chain('localhost.pem')
    #
    # coro = loop.create_server(AsyncServer, *("", 9000), ssl=context)

    server = loop.run_until_complete(coro)
    print('Listening at {}'.format(("", 9000)))

    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()
