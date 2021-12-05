package com.houseofkraft.nsp.networking;

/*
 * Next Socket Protocol Client
 * Copyright (c) 2021 houseofkraft
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for specific language governing permissions and
 * limitations under the License.
 */

import com.houseofkraft.nsp.encryption.AES;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.HashMap;

public class Client {
    private final long timestamp = System.currentTimeMillis();
    private String id = AES.generatePassword(2, "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM");
    private boolean kicked = false, banned = false, idMode = false;

    private ClientManager handlerThread;
    private final DataInputStream inputStream;
    private final DataOutputStream outputStream;
    private final Socket socket;
    private final String ipPort, ipAddress;
    private long keepAlive = System.currentTimeMillis() + NSPServer.keepAlive * 1000L;

    /** Bans the Client from the Server */
    public void ban() { this.banned = true; }

    /** Kicks the Client from the Server */
    public void kick() { this.kicked = true; }

    /** Kicks the Client from the Server */
    public void stop() { this.kicked = true; }

    /** @return If the Client is Kicked */
    public boolean isKicked() { return this.kicked; }

    /** @return If the Client is Banned */
    public boolean isBanned() { return this.banned; }

    /** @return Keep Alive Milliseconds */
    public long getKeepAlive() { return this.keepAlive; }

    /** @return Input Stream */
    public DataInputStream getInputStream() { return this.inputStream; }

    /** @return Output Stream */
    public DataOutputStream getOutputStream() { return this.outputStream; }

    /**
     * Resets the Keep Alive to the specified seconds delay in the Options.
     * @return Client Builder
     */
    public Client resetKeepAlive() {
        this.keepAlive = System.currentTimeMillis() + NSPServer.keepAlive * 1000L;
        return this;
    }

    /** @return Initial Connection Timestamp */
    public long getTimestamp() { return this.timestamp; }

    /** @return Socket Instance */
    public Socket getSocket() { return this.socket; }

    /**
     * @param port Return the address with the Port
     * @return Bound IP Address with Port Option
     */
    public String getIP(boolean port) {
        if (port) {
            return this.ipPort;
        } else { return this.ipAddress; }
    }

    /** @return ID Identifier */
    public String getID() { return this.id; }

    /**
     * Changes the Identifier Hostname when the mode is changed to ID.
     * @param hostname Hostname
     */
    public void setID(String hostname) { this.id = hostname; }

    /**
     * Sets the Identifier mode to either ID Mode or IP Mode.
     * @param idMode ID Mode
     * @return Client Builder
     */
    public Client setIDMode(boolean idMode) { this.idMode = idMode; return this; }

    /**
     * Sets the Client Handler Thread for the Server.
     * @param handlerThread Client Handler Thread
     * @return Client Builder
     */
    public Client setThread(ClientManager handlerThread) { this.handlerThread = handlerThread; return this; }

    /** @return Client Manager Thread */
    public ClientManager getThread() { return this.handlerThread;}

    /** Starts the Client Manager Thread */
    public Client startThread() {
        this.handlerThread.start();
        return this;
    }

    /**
     * @param port Return with Port Included
     * @return Preferred Identifier
     */
    public String getIdentifier(boolean port) {
        if (idMode) {
            return this.id;
        } else {
            if (port) {
                return this.ipPort;
            } else { return this.ipAddress; }
        }
    }

    /**
     * Sends a Message using the built-in OutputStream.
     * @param packet ByteArray Packet
     * @return Client Builder
     */
    public boolean sendMessage(byte[] packet) {
        return Messages.sendMessage(this.outputStream, packet);
    }

    /**
     * Reads the Message using the built-in InputStream.
     * @param parser Packet Parser
     * @return Read Message HashMap
     * @throws GeneralSecurityException If there is a decryption error.
     * @throws IOException If there is a socket error.
     */
    public HashMap<byte[], byte[]> readMessage(PacketParser parser) throws GeneralSecurityException,
            IOException {

        return Messages.readMessage(this.inputStream, parser);
    }

    /**
     * Reads the Message using the built-in InputStream.
     * @param parser Packet Parser
     * @return Read Message String
     * @throws GeneralSecurityException If there is a decryption error.
     * @throws IOException If there is a socket error.
     */
    public HashMap<String, String> readMessageString(PacketParser parser) throws GeneralSecurityException,
            IOException {

        HashMap<byte[], byte[]> message = Messages.readMessage(this.inputStream, parser);
        HashMap<String, String> output = new HashMap<>();
        message.forEach((k,v) -> output.put(new String(k), new String(v)));

        return output;
    }

    public Client(Socket socket) throws IOException {
        this.inputStream = new DataInputStream(socket.getInputStream());
        this.outputStream = new DataOutputStream(socket.getOutputStream());
        this.ipPort = socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
        this.ipAddress = socket.getInetAddress().getHostAddress();
        this.socket = socket;
    }
}
