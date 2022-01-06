package com.houseofkraft.nsp.networking;

/*
 * Next Socket Protocol Client
 * Copyright (c) 2022 houseofkraft
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
import com.houseofkraft.nsp.listener.NSPListener;
import com.houseofkraft.nsp.tool.ThreadTimer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;

import static com.houseofkraft.nsp.networking.NSPHeader.Message.*;

public class NSP {
    private String serverAddress, hostname;
    private Socket socket;
    private DataInputStream dis;
    private DataOutputStream dos;
    private HandshakeReader options;
    private AES cryptHandler;

    private int compressLevel, serverPort;
    private volatile boolean idMode = false, connected = false, updateClientList = false;

    private final String IP_REGEX = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    private final Pattern IP_PATTERN = Pattern.compile(IP_REGEX);
    private final PacketParser DEFAULT_PARSER = new PacketParser();
    private final ConnectionManager connectThread = new ConnectionManager();
    private final ArrayList<NSPListener> listeners = new ArrayList<>();
    private final PacketParser parser = new PacketParser();

    /** @return Server Address */
    public String getAddress() { return serverAddress; }

    /** @return Socket Instance */
    public Socket getSocket() { return socket; }

    /**
     * Sets a custom Socket to be used for when you need to add modifications to it, such as VPN protect on Android.
     * @param socket Socket Instance
     * @return Client Builder
     */
    public NSP setSocket(Socket socket) { this.socket = socket; return this; }

    /**
     * Changes the Server Address to connect to.
     * @param serverAddress Server Address
     * @return Client Builder
     */
    public NSP setAddress(String serverAddress) { this.serverAddress = serverAddress; return this; }

    /** @return Encryption Handler **/
    public AES getEncryption() { return cryptHandler; }

    /**
     * Sets the Encryption Handler to be used with the Server.
     * @param cryptHandler Encryption Handler
     * @return Client Builder
     */
    public NSP setEncryption(AES cryptHandler) { this.cryptHandler = cryptHandler; return this; }

    /** @return Deflate Level */
    public int getDeflateLevel() { return compressLevel; }

    /**
     * Changes the Deflation Level used with the Server.
     * @param compressLevel Deflate Level
     * @return Client Builder
     */
    public NSP setDeflateLevel(int compressLevel) { this.compressLevel = compressLevel; return this; }

    /** @return Server Port */
    public int getPort() { return serverPort; }

    /**
     * Changes the Server Port to connect to.
     * @param serverPort Server Port
     * @return Client Builder
     */
    public NSP setPort(int serverPort) { this.serverPort = serverPort; return this; }

    /**
     * Adds a new NSPListener used for detecting new messages, clients, etc.
     * @param listener Client Listener
     * @return Client Object
     */
    public NSP addListener(NSPListener listener) { this.listeners.add(listener); return this; }

    /**
     * Broadcast a Message to every Client connected.
     * @param packet Packet
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     * @return Client Builder
     */
    public NSP broadcast(Packet packet) throws GeneralSecurityException, IOException {
        Messages.sendMessage(dos, packet.parseBytes());
        return this;
    }

    /**
     * Sends a Message to a specific Client Identifier.
     * @param packet Packet
     * @param identifier Client Identifier
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     * @return Client Builder
     */
    public NSP send(Packet packet, String identifier) throws GeneralSecurityException, IOException {
        Messages.sendMessage(dos, packet.addEntry("ssnp-sender", identifier).parseBytes());
        return this;
    }

    /**
     * Initializes a connection by testing the IP address and Port ranges, then creates a new Socket
     * and DataInputStream/DataOutputStream objects.
     * @param address Server Address
     * @param port Server Port
     * @param timeout Connection Timeout in Seconds
     * @throws IOException If there is a socket error.
     */
    private void initializeConnection(String address, int port, int timeout) throws IOException {
        if (!IP_PATTERN.matcher(address).matches()) { throw new SocketException("IP Address invalid"); }
        if (port < 1 || port > 65535) { throw new SocketException("Port out of range"); }
        if (address.equals("")) { throw new SocketException("Address cannot be empty"); }

        this.socket = new Socket();
        this.socket.connect(new InetSocketAddress(address, port), timeout*1000);
        this.dis = new DataInputStream(socket.getInputStream());
        this.dos = new DataOutputStream(socket.getOutputStream());
    }

    /**
     * Closes the Socket only for a specific reason.
     * @param reason Disconnection Reason
     * @throws IOException If there is a socket error.
     * @return Client Builder
     */
    private NSP socketClose(String reason) throws IOException {
        this.dis.close();
        this.dos.close();
        this.socket.close();
        this.connectThread.interrupt();
        this.connected = false;
        listeners.forEach(listener -> listener.socketDisconnected(reason));
        return this;
    }

    /**
     * Closes the Socket and sends a disconnection message for a specific reason.
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     * @return Client Builder
     */
    public NSP close() throws GeneralSecurityException, IOException {
        Messages.sendMessage(dos, new Packet().addEntry(STATUS.toString(), DISCONNECT.toString()).parseBytes());
        socketClose("client disconnection");
        return this;
    }

    /**
     * Changes the Identifier mode to ID Mode or IP Mode.
     * @param idMode ID/IP Mode
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     * @return Client Builder
     */
    public NSP setIDMode(boolean idMode) throws GeneralSecurityException, IOException {
        this.idMode = idMode;
        if (connected) {
            // If changing this mode after Handshake Process, tell the Server while connected.
            if (idMode) {
                Messages.sendMessage(dos, new ModifiedPacket().addEntry(STATUS.toString(), "id-mode").parseBytes());
            } else {
                Messages.sendMessage(dos, new ModifiedPacket().addEntry(STATUS.toString(), "ip-mode").parseBytes());
            }
        }
        return this;
    }

    /**
     * Change the Hostname for the Server Identification.
     * @param hostname Hostname
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     * @return Client Builder
     */
    public NSP setHostname(String hostname) throws GeneralSecurityException, IOException {
        this.hostname = hostname;
        if (connected) {
            // If changing this mode after Handshake Process, tell the Server while connected.
            Messages.sendMessage(dos, new ModifiedPacket()
                    .addEntry(STATUS.toString(), "hostname")
                    .addEntry("hostname", hostname)
                    .parseBytes());
        }
        return this;
    }

    public void getClientList() throws GeneralSecurityException, IOException {
        if (options.getDiscloseClient()) {
            // Attempt to make a request to disclose the Client List.
            Messages.sendMessage(dos, new ModifiedPacket().addEntry(STATUS.toString(), "client-list").parseBytes());
        }
    }

    /**
     * @return Synchronized Client List
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     */
    public ArrayList<String> getClientListSync() throws GeneralSecurityException, IOException {
        getClientList();
        while (!updateClientList) {
            Thread.onSpinWait();
        }
        updateClientList = false;
        return options.getClientList();
    }

    /**
     * Initializes a connection to the Server to receive information about the handshake and timeout, then disconnect.
     * @param address Server Address
     * @param port Server Port
     * @param timeout Timeout
     * @return HandshakeReader
     * @throws IOException If there is an encryption error.
     * @throws GeneralSecurityException If there is a socket error.
     */
    public HandshakeReader handshake(String address, int port, int timeout) throws IOException, GeneralSecurityException {
        initializeConnection(address, port, timeout);
        HandshakeReader reader = new HandshakeReader(Messages.readMessageString(dis, DEFAULT_PARSER, timeout));
        close();
        return reader;
    }

    /**
     * Initializes a connection to the Server to receive information about the handshake, then disconnect.
     * @param address Server Address
     * @param port Server Port
     * @return HandshakeReader
     * @throws IOException If there is an encryption error.
     * @throws GeneralSecurityException If there is a socket error.
     */
    public HandshakeReader handshake(String address, int port) throws IOException, GeneralSecurityException {
        return handshake(address, port, 15);
    }

    /**
     * Initializes a connection with the Server, and automatically accepts the Handshake Process, starting
     * the connection running.
     *
     * @param address Server Address
     * @param port Server Port
     * @return HandshakeReader
     * @throws IOException If there is an encryption error.
     * @throws GeneralSecurityException If there is a socket error.
     */
    public HandshakeReader connect(String address, int port, int timeout) throws IOException, GeneralSecurityException {
        initializeConnection(address, port, timeout);
        options = new HandshakeReader(Messages.readMessageString(dis, DEFAULT_PARSER));
        Packet acceptPacket;

        if (options.getEncryption()) {
            if (this.cryptHandler == null) {
                close();
                throw new SocketException("Encryption required but not configured");
            }
            parser.setEncryption(this.cryptHandler);
        }

        if (options.getDeflateLevel() > 0) {
            parser.setDeflate(true);
            compressLevel = options.getDeflateLevel();
        }

        acceptPacket = new ModifiedPacket().addEntry(STATUS.toString(), ACCEPT.toString());
        if (hostname != null) { idMode = true; acceptPacket.addEntry("hostname", hostname); }
        if (idMode) { acceptPacket.addEntry("identify", "id"); }
        Messages.sendMessage(dos, acceptPacket.parseBytes());

        this.connected = true;
        this.connectThread.start();
        return options;
    }

    /**
     * Initializes a connection with the Server that is using Private Mode to hide the network, starting the connection
     * running.
     *
     * @param address Server Address
     * @param port Server Port
     * @throws IOException If there is an encryption error.
     * @throws GeneralSecurityException If there is a socket error.
     */
    public HandshakeReader connectPrivate(String address, int port, int timeout) throws IOException, GeneralSecurityException {
        initializeConnection(address, port, timeout);

        if (cryptHandler != null) {
            parser.setEncryption(cryptHandler);
        }
        parser.setDeflate(compressLevel>0);

        Packet acceptPacket = new ModifiedPacket().addEntry(STATUS.toString(), ACCEPT.toString());
        if (hostname != null) { idMode = true; acceptPacket.addEntry("hostname", hostname); }
        if (idMode) { acceptPacket.addEntry("identify", "id"); }
        Messages.sendMessage(dos, acceptPacket.parseBytes());

        // Expect the encrypted Handshake to be sent after the connection is initialized.
        options = new HandshakeReader(Messages.readMessageString(dis, parser));

        this.connected = true;
        this.connectThread.start();

        return options;
    }

    /**
     * Scans the specified range of IP addresses starting with 192.168.1.X for any Servers currently running on
     * those addresses, and attempts to Handshake and receive information. If Obtainable is enabled, only servers
     * that are guaranteed to work with the currently set options will be added to the list. This feature is only
     * recommended being used on local Wi-Fi networks!
     *
     * @param port Port to Scan
     * @param start IP Address Start
     * @param end IP Address End
     * @param obtainable If the address 
     * @return HashMap of IP Address and HandshakeReader of successful Servers
     */
    public HashMap<String, HandshakeReader> scan(int port, int start, int end, boolean obtainable) throws GeneralSecurityException, IOException {
        HashMap<String, HandshakeReader> output = new HashMap<>();
        for (int i=start; i<end; i++) {
            String address = "192.168.1."+i;
            HandshakeReader reader = handshake(address, port, 3);
            if (obtainable) {
                if (reader.getEncryption() && cryptHandler != null) {
                    output.put(address, reader);
                }
            } else {
                output.put(address, reader);
            }
        }
        return output;
    }

    /**
     * Scans the range of IP addresses from 192.168.1.2 to 192.168.1.254 for any Servers currently running on
     * those addresses, and attempts to Handshake and receive information. If Obtainable is enabled, only servers
     * that are guaranteed to work with the currently set options will be added to the list. This feature is only
     * recommended being used on local Wi-Fi networks!
     *
     * @param port Port to Scan
     * @param obtainable If the address
     * @return HashMap of IP Address and HandshakeReader of successful Servers
     */
    public HashMap<String, HandshakeReader> scan(int port, boolean obtainable) throws GeneralSecurityException, IOException {
        return scan(port, 2, 254, obtainable);
    }

    /**
     * Initializes a connection with the Server using the Address and Port specified in the Server Options.
     * @return HandshakeReader
     * @throws IOException If there is an encryption error.
     * @throws GeneralSecurityException If there is a socket error.
     * @see #connect(String, int, int)
     */
    public HandshakeReader connect() throws GeneralSecurityException, IOException {
        return connect(serverAddress, serverPort, 5);
    }

    /**
     * Initializes a private connection with the Server using the Address and Port specified in the Server Options.
     * @return NSP
     * @throws IOException If there is an encryption error.
     * @throws GeneralSecurityException If there is a socket error.
     * @see #connect(String, int, int)
     */
    public HandshakeReader connectPrivate() throws GeneralSecurityException, IOException {
        return connectPrivate(serverAddress, serverPort, 60);
    }

    /**
     * Initializes a handshake to the Server using the Address and Port specified in the Server Options.
     * @return HandshakeReader
     * @throws IOException If there is an encryption error.
     * @throws GeneralSecurityException If there is a socket error.
     * @see #handshake(String, int) 
     */
    public HandshakeReader handshake() throws GeneralSecurityException, IOException {
        return handshake(serverAddress, serverPort);
    }

    /** @return Server Options */
    public HandshakeReader getOptions() { return this.options; }

    /** Initializes NSP Client with Address and Port */
    public NSP(String address, int port) {
        this.serverAddress = address;
        this.serverPort = port;
    }

    public static class HandshakeReader {
        private int totalOnline = -1;
        private int maxUsers = -1;
        private int maxConcurrent = -1;
        private int deflateLevel = 0;
        private int keepAlive = 0;

        private boolean whiteListEnabled = false;
        private boolean blackListEnabled = false;
        private boolean cryptEnabled = false;
        private boolean hideIP = false;
        private boolean whitelisted = false;
        private boolean banned = false;
        private boolean connectMax = false;
        private boolean ipMax = false;
        private boolean discloseClient = false;

        private boolean connectError = false;

        private final HashMap<String, String> packet;
        private ArrayList<String> clientList;

        /** @return Total Online */
        public int getOnline() { return totalOnline; }

        /** @return Max Users */
        public int getMaxUsers() { return maxUsers; }

        /** @return Max Concurrent */
        public int getMaxConcurrent() { return maxConcurrent; }

        /** @return Keep Alive Time */
        public int getKeepAlive() { return keepAlive; }

        /** @return Deflate Level */
        public int getDeflateLevel() { return deflateLevel; }

        /** @return Whitelist Enabled */
        public boolean getWhiteList() { return whiteListEnabled; }

        /** @return Blacklist Enabled */
        public boolean getBlackList() { return blackListEnabled; }

        /** @return Encryption Enabled */
        public boolean getEncryption() { return cryptEnabled; }

        /** @return IP Always Hidden */
        public boolean getHideIP() { return hideIP; }

        /** @return Deflated HashMap */
        public HashMap<String, String> getHashMap() { return this.packet; }

        /** @return If there is a connection error such as banned, blacklisted, max users, etc. */
        public boolean isError() { return this.connectError; }

        /** @return If Client is Banned */
        public boolean isBanned() { return this.banned; }

        /** @return If Client is Whitelisted */
        public boolean isWhiteListed() { return this.whitelisted; }

        /** @return If Maximum Connections are Reached */
        public boolean isMaxConnection() { return this.connectMax; }

        /** @return If Maximum Concurrent Connections are Reached */
        public boolean isMaxConcurrent() { return this.ipMax; }

        /** @return If Client is Blacklisted/Banned */
        public boolean isBlackListed() { return isBanned(); }

        /** @return Disclose Clients Enabled */
        public boolean getDiscloseClient() { return this.discloseClient; }

        /** @return Client List */
        public ArrayList<String> getClientList() { return this.clientList; }

        /**
         * Reads a Handshake using a specified Packet, and simplify the output.
         * @param packet HashMap String Input
         */
        public HandshakeReader(HashMap<String, String> packet) {
            this.packet = packet;
            this.clientList = new ArrayList<>();

            // First, check if the Client received a disconnect packet which could indicate kicked, banned, etc.
            if (packet.containsKey(STATUS.toString()) && packet.containsValue(DISCONNECT.toString())) {
                connectError = true;
                String reason = packet.get("reason");
                if (reason != null) {
                    switch (reason) {
                        case "blacklist" -> banned = true;
                        case "whitelist" -> whitelisted = true;
                        case "maximum connections reached" -> connectMax = true;
                        case "exceeding maximum ip connections" -> ipMax = true;
                    }
                }
            } else {
                packet.forEach((status, value) -> {
                    if (status.contains("cli-")) {
                        clientList.add(value);
                    }
                    switch (status) {
                        // Parse the String values into their respective types, and move it into the proper variable
                        // based on the type.
                        case "online" -> this.totalOnline = Integer.parseInt(value);
                        case "max-user" -> this.maxUsers = Integer.parseInt(value);
                        case "max-con" -> this.maxConcurrent = Integer.parseInt(value);
                        case "compression" -> this.deflateLevel = Integer.parseInt(value);
                        case "encryption" -> this.cryptEnabled = Boolean.parseBoolean(value);
                        case "whitelist" -> this.whiteListEnabled = Boolean.parseBoolean(value);
                        case "blacklist" -> this.blackListEnabled = Boolean.parseBoolean(value);
                        case "hide-ip" -> this.hideIP = Boolean.parseBoolean(value);
                        case "keep-alive" -> this.keepAlive = Integer.parseInt(value);
                        case "client-list" -> {
                            switch (value) {
                                case "empty" -> {}
                                case "non-disclose" -> discloseClient = false;
                            }
                        }
                    }
                });
            }
        }
    }

    private class ConnectionManager extends Thread {
        /**
         * @param packet Packet
         * @param value Value to get from Packet
         * @return Safe Value or Default
         */
        private String getSafeValue(HashMap<String, String> packet, String value) {
            return (packet.get(value) != null) ? packet.get(value) : "";
        }

        @Override
        public void run() {
            int keepAlive = options.getKeepAlive();
            if (keepAlive > 0) {
                ThreadTimer timer = new ThreadTimer().setSeconds(keepAlive-1);
                ThreadTimer.TimerListener listener = new ThreadTimer.TimerListener() {
                    @Override
                    public void timerComplete() throws GeneralSecurityException, IOException {
                        // Send the keep-alive message to prevent disconnection due to timeout.
                        Messages.sendMessage(dos, new ModifiedPacket()
                                .addEntry(STATUS.toString(), "keep-alive")
                                .parseBytes());
                        timer.startTimer();
                    }

                    @Override
                    public void timerError(String errorCode) { timer.startTimer(); }
                };
                timer.addListener(listener).startTimer();
            }

            // Read any messages that are being received to the Client.
            while (!socket.isClosed() && !isInterrupted() && connected) {
                try {
                    HashMap<String, String> packet = Messages.readMessageString(dis, parser);
                    if (packet != null && packet.size() > 0) {
                        if (packet.containsKey(STATUS.toString())) {
                            switch (packet.get(STATUS.toString())) {
                                case "disconnect" -> socketClose(getSafeValue(packet, "reason"));
                                case "client-connect" -> {
                                    String identifier = getSafeValue(packet, "identifier");
                                    listeners.forEach(listeners -> listeners.clientConnected(identifier));
                                }
                                case "client-disconnect" -> {
                                    String identifier = getSafeValue(packet, "identifier");
                                    String reason = getSafeValue(packet, "reason");
                                    listeners.forEach(listeners -> listeners.clientDisconnected(identifier, reason));
                                }

                                case "client-list-success" -> {
                                    // This would most likely be initialized from the getClientList method.
                                    ArrayList<String> newClientList = new ArrayList<>();
                                    packet.forEach((key, value) -> {
                                        if (key.contains("cli-")) {
                                            newClientList.add(value);
                                        }
                                    });
                                    if (options != null) {
                                        options.clientList = newClientList;
                                    }
                                    updateClientList = true;
                                    listeners.forEach(listener -> listener.clientListUpdate(newClientList));
                                }
                                default -> {
                                    String identifier = (packet.get("identifier") != null) ? packet.get("identifier") : "";
                                    listeners.forEach(listener -> listener.messageReceived(identifier, packet));
                                }
                            }
                        } else {
                            // Relay the message to the NSPListeners and attempt to get the original Identifier.
                            String identifier = (packet.get("identifier") != null) ? packet.get("identifier") : "";
                            listeners.forEach(listener -> listener.messageReceived(identifier, packet));
                        }
                    }
                } catch (IOException io) {
                    // The server has most likely been closed if there is an IOException at this point, process accordingly.
                    try {
                        if (connected) {
                            socketClose("server disconnection");
                        }
                    } catch (IOException ignored) {}
                } catch (GeneralSecurityException ignored) {}
            }
        }
    }

    private class ModifiedPacket extends Packet {
        /**
         * This is used for creating a new Packet instance with the correct encryption and compression
         * without having to manually set it in a regular instance.
         */
        public ModifiedPacket() {
            AES encryption = cryptHandler;
            int deflateLevel = compressLevel;

            if (encryption != null) { this.setEncryption(encryption); }
            this.setDeflateLevel(deflateLevel);
        }

        /** @return Raw Packet Instance */
        public Packet toPacket() { return this; }
    }
}