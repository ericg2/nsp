package com.houseofkraft.nsp.networking;

/*
 * Next Socket Protocol Server
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
import com.houseofkraft.nsp.listener.InternalListener;
import com.houseofkraft.nsp.listener.ServerListener;
import com.houseofkraft.nsp.tool.ThreadTimer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.Deflater;

import static com.houseofkraft.nsp.networking.NSPHeader.Message.*;

public class NSPServer {
    protected static volatile ServerOption option;
    protected static volatile Queue<Client> clientList;
    protected static volatile ArrayList<ServerListener> serverListeners;
    protected static volatile ServerSocket server;
    protected static volatile PacketParser parser;
    protected static volatile HashMap<String, String> appendHandshake;

    public static volatile ArrayList<InternalListener> internalListeners;
    public static int keepAlive;

    private Thread acceptorThread;
    private Thread connectManagerThread;

    /**
     * Broadcasts a ByteArray to every Client that is currently connected.
     * @param sendBytes ByteArray To Send
     * @return NSPServer Instance
     */
    public NSPServer broadcast(byte[] sendBytes) { clientList.forEach((k -> k.sendMessage(sendBytes))); return this; }

    /**
     * Broadcasts a ByteArray to a specified List of Clients.
     * @param sendBytes ByteArray To Send
     * @param group List Containing Client Object Group
     * @return NSPServer Instance
     */
    public NSPServer broadcast(byte[] sendBytes, List<Client> group) { group.forEach((k) -> k.sendMessage(sendBytes)); return this; }

    /**
     * Enables Incoming Connections by Activating the ConnectionActivator Thread.
     * @see #connectManagerThread
     * @return NSPServer Instance
     */
    public NSPServer allowIncoming() { if (acceptorThread.isInterrupted()) { acceptorThread.start(); } return this; }

    /**
     * Disables Incoming Connections by Deactivating the ConnectionActivator Thread.
     * @see #connectManagerThread
     * @return NSPServer Instance
     */
    public NSPServer denyIncoming() { if (!acceptorThread.isInterrupted()) { acceptorThread.interrupt(); } return this; }

    /** @return Total Amount of Connected Clients */
    public int totalConnected() { return clientList.size(); }

    /**
     * Adds a ServerListener to the list, which sends Events during a client connection, disconnection, and when there
     * is a new message. This is fully asynchronous and doesn't require any blocking methods.
     *
     * @param listener ServerListener Object
     * @return NSPServer Instance
     */
    public NSPServer addListener(ServerListener listener) { serverListeners.add(listener); return this; }

    /**
     * Appends the specified HashMap into the Packet that is sent when doing the initial Handshake, and will be shown
     * to any Clients that are connecting to the Server.
     * @param handshake String HashMap to Append to Handshake
     * @return NSPServer Instance
     */
    public NSPServer setCustomHandshake(HashMap<String, String> handshake) { appendHandshake = handshake; return this; }

    /**
     * Updates the built-in PacketParser used for properly decoding incoming Packets. This sets the proper encryption,
     * and compression, and then resets the keepAlive variable.
     */
    private void updateParser() {
        AES encryption = option.getEncryption();
        int defLevel = option.getDeflateLevel();

        if (encryption != null) { parser.setEncryption(encryption); }
        if (defLevel > 0) { parser.setDeflate(true); }
        keepAlive = option.getKeepAlive();
    }

    /** @return Server Options */
    public ServerOption getOptions() {
        return option;
    }

    /**
     * Activates the server connection by creating the new ServerSocket instance, and starting the SocketAcceptor
     * and global ConnectionManager Threads.
     *
     * @throws IOException If there are any errors related to starting the Server.
     * @return NSPServer Instance
     */
    public NSPServer bind() throws IOException {
        server = new ServerSocket(option.getPort());
        keepAlive = option.getKeepAlive();

        this.acceptorThread = new SocketAcceptor();
        this.acceptorThread.start();

        this.connectManagerThread = new ConnectionManager();
        this.connectManagerThread.start();
        updateParser();

        serverListeners.forEach(ServerListener::serverConnected);
        return this;
    }

    /**
     * Disconnects all the Clients from the Server, and then closes the ServerSocket.
     * @throws IOException If there are any errors while closing the Server.
     * @return NSPServer Instance
     */
    public NSPServer close() throws IOException {
        clientList.forEach(Client::kick);
        serverListeners.forEach(ServerListener::serverDisconnected);
        server.close();
        return this;
    }

    /**
     * This function is designed to be used to return the list of Preferred Identifiers for each Client
     * connected, rather than always giving away the IP address like the getClients function would. This is intended
     * for the handshaking process or when the Client requests the list of all currently connected clients. Each client
     * on the returned list will either have its IP address, or its custom ID depending on which one it chose.
     *
     * @see #getIPClients(String, boolean)
     * @return Safe List of Connected Clients
     */
    public static ArrayList<String> getConnectedList() {
        ArrayList<String> connectedReturnList = new ArrayList<>();
        clientList.forEach((k) -> connectedReturnList.add(k.getIdentifier(true)));
        return connectedReturnList;
    }

    /**
     * @return A network send-able Packet containing the Connection Time and Preferred ID of each Client.
     */
    protected static Packet getConnectedPacket() {
        HashMap<byte[], byte[]> customMap = new HashMap<>();
        Packet output = new Packet().setDeflateLevel(Deflater.BEST_COMPRESSION);

        clientList.forEach((k) -> customMap.put(String.valueOf(k.getTimestamp()).getBytes(), k.getIdentifier(true).getBytes()));
        return output.setCustomMapByte(customMap);
    }

    /**
     * Looks up the specified Client Identifier with Optional Port and returns a List of all Client instances containing
     * the Identifier.
     *
     * @param identifier Client Identifier
     * @param port If port should be used when looking up IP
     * @return List of Client Objects containing Identifier
     */
    public static ArrayList<Client> getClientStatic(String identifier, boolean port) {
        ArrayList<Client> clientReturnList = new ArrayList<>();
        clientList.forEach((k) -> {
            if (identifier.equals(k.getIdentifier(port))) {
                clientReturnList.add(k);
            }
        });
        return clientReturnList;
    }

    /**
     * Looks up the specified Client Identifier with Optional Port and returns a List of all Client instances containing
     * the Identifier.
     *
     * @param identifier Client Identifier
     * @param port If port should be used when looking up IP
     * @return List of Client Objects containing Identifier
     */
    public ArrayList<Client> getClients(String identifier, boolean port) {
        ArrayList<Client> clientReturnList = new ArrayList<>();
        clientList.forEach((k) -> {
            if (identifier.equals(k.getIdentifier(port))) {
                clientReturnList.add(k);
            }
        });
        return clientReturnList;
    }


    /** @return Client List  */
    public Queue<Client> getClientList() { return clientList; }

    /**
     * Looks up the specified Client IP Address with Optional Port and returns a List of all Client instances containing
     * the IP Address.
     *
     * @param ipAddress Client IP Address
     * @param port If port should be used
     * @return List of Client Objects containing IP Address
     */
    public ArrayList<Client> getIPClients(String ipAddress, boolean port) {
        ArrayList<Client> clientReturnList = new ArrayList<>();
        clientList.forEach((k) -> {
            if (ipAddress.equals(k.getIP(port))) {
                clientReturnList.add(k);
            }
        });
        return clientReturnList;
    }

    /** @return Returns true if Thread and Server are running, false otherwise. */
    public boolean isRunning() { return (!this.connectManagerThread.isInterrupted() && !server.isClosed()); }

    /**
     * Initializes new Instance of the Server, creating the required Parser and ArrayLists using the specified
     * options.
     *
     * @param options Server Options
     */
    public NSPServer(ServerOption options) {
        option = options;
        serverListeners = new ArrayList<>();
        clientList = new ConcurrentLinkedQueue<>();
        parser = new PacketParser();
        internalListeners = new ArrayList<>();
        appendHandshake = new HashMap<>();

        updateParser();

        // Add a custom listener used for when clients are connected and disconnected to announce publicly.
        addListener(new ServerListener() {
            @Override public void messageReceived(Client client, HashMap<String, String> packet) {}
            @Override public void serverDisconnected() {}
            @Override public void serverConnected() {}

            @Override
            public void clientConnected(Client client) {
                try {
                    if (NSPServer.option.getAnnounceClientActions()) {
                        // Send a message to any connected Clients telling about the connection
                        broadcast(new ModifiedPacket()
                                .addEntry(STATUS.toString(), "client-connect")
                                .addEntry("identifier", client.getIdentifier(true))
                                .parseBytes());
                    }
                } catch (IOException | GeneralSecurityException ignored) {}
            }

            @Override
            public void clientDisconnected(Client client, String reason) {
                try {
                    if (NSPServer.option.getAnnounceClientActions()) {
                        // Send a message to any connected Clients telling about the connection
                        broadcast(new ModifiedPacket()
                                .addEntry(STATUS.toString(), "client-disconnect")
                                .addEntry("identifier", client.getIdentifier(true))
                                .addEntry("reason", reason)
                                .parseBytes());
                    }
                } catch (IOException | GeneralSecurityException ignored) {}
            }
        });
    }

    /**
     * Initializes new Instance of the Server, without having to specify a specific Port in the Options.
     * @param port Port
     * @param options Server Options
     */
    public NSPServer(int port, ServerOption options) {
        this(options);
        option.setPort(port);
    }
}

class ConnectionActivator extends Thread {
    private final Socket socket;
    private Client client;

    /**
     * This ClientActivator is used after the SocketAcceptor first receives a possibly connecting Client, and will
     * initialize the Handshake Process by checking the criteria such as whitelist, blacklist, max users/current,
     * etc. If these pass, the Server will send an unencrypted message stating all the required information, including
     * if encryption or compression is being used. Finally, it will wait for a properly encoded message stating the
     * client has successfully connected, then adding it to the list and initializing a new ClientManager.
     *
     * @param socket Possible Connected Socket
     */
    public ConnectionActivator(Socket socket) { this.socket = socket; }

    private void close(String reason) throws IOException, GeneralSecurityException {
        this.client.sendMessage(
                new Packet()
                        .addEntry(STATUS.toString(), DISCONNECT.toString())
                        .addEntry("reason", reason)
                        .parseBytes()
        );
        this.client.getSocket().close();
        this.client.kick();
        interrupt();
    }

    @Override
    public void run() {
        try {
            // Make sure the client should be allowed to connect by checking whitelist, blacklist,
            // max concurrent/total connections, etc. Also, preload the variables to ensure these cannot be
            // modified while the Handshake occurs.
            ArrayList<String> blackList = NSPServer.option.getBlackList();
            ArrayList<String> whiteList = NSPServer.option.getWhiteList();
            HashMap<String, String> appendHandshake = NSPServer.appendHandshake;

            int maxUsers = NSPServer.option.getMaxUsers();
            int maxConcurrent = NSPServer.option.getMaxConcurrent();
            boolean privateMode = NSPServer.option.getHiddenNetwork();

            this.client = new Client(socket);

            if (maxUsers > 0 && NSPServer.clientList.size() >= NSPServer.option.getMaxUsers()) {
                close("maximum connections reached");
            }

            // Check the IP address for blacklist/whitelisting to prevent bypassing from using different ID.
            if (blackList != null && blackList.size() > 0 && blackList.contains(client.getIP(false))) {
                close("blacklist");
            }

            if (whiteList != null && whiteList.size() > 0 && !whiteList.contains(client.getIP(false))) {
                close("whitelist");
            }

            // Check the concurrent connections if they are enabled, which prevents connections from the same IP
            // address from joining the socket more than the specified amount of times.
            if (maxConcurrent > 0) {
                String socketIP = client.getIP(false);
                int ipConnections = (int) NSPServer.clientList.stream().filter(cli -> cli.getIP(false).contains(socketIP)).count();

                if (ipConnections >= NSPServer.option.getMaxConcurrent()) {
                    close("exceeding maximum ip connections");
                }
            }

            // Start the handshake process by sending the public available information, without any
            // encryption, compression, etc. If private mode is enabled, then skip the Handshake process and
            // expect the encrypted response regardless.
            Packet infoPacket = new Packet()
                    .addEntry("online", String.valueOf(NSPServer.clientList.size()))
                    .addEntry("max-user", String.valueOf(maxUsers))
                    .addEntry("max-con", String.valueOf(maxConcurrent))
                    .addEntry("compression", String.valueOf(NSPServer.option.getDeflateLevel()))
                    .addEntry("encryption", String.valueOf(NSPServer.option.getEncryption() != null))
                    .addEntry("whitelist", String.valueOf(whiteList != null && whiteList.size()>0))
                    .addEntry("blacklist", String.valueOf(blackList != null && blackList.size()>0))
                    .addEntry("keep-alive", String.valueOf(NSPServer.option.getKeepAlive()))
                    .addEntry("hide-ip", String.valueOf(NSPServer.option.isHideAllIP()));

            appendHandshake.forEach(infoPacket::addEntry);

            // If the option to disclose the entire user-list is enabled, then add it to the Packet list.
            if (NSPServer.option.getDiscloseClientList()) {
                if (NSPServer.clientList.size() > 0) {
                    AtomicInteger counter = new AtomicInteger(0);
                    NSPServer.getConnectedList().forEach((cli -> {
                        infoPacket.addEntry("cli-" + counter, cli);
                        counter.set(counter.get() + 1);
                    }));
                } else {
                    infoPacket.addEntry("client-list", "empty");
                }
            } else {
                infoPacket.addEntry("client-list", "non-disclose");
            }

            if (!privateMode) {
                client.sendMessage(infoPacket.parseBytes());
            }

            final boolean[] timerRunning = {true};
            HashMap<String, String> packet;
            new ThreadTimer()
                    .setSeconds(NSPServer.option.getHandshakeTimeout())
                    .addListener(new ThreadTimer.TimerListener() {
                        @Override public void timerComplete() { timerRunning[0] = false; }
                        @Override public void timerError(String errorCode) {}
                    });

            while (timerRunning[0] && !isInterrupted() && !client.getSocket().isClosed()) {
                // Read all incoming messages, and if its properly formatted then it will be able to connect
                packet = client.readMessageString(NSPServer.parser);

                if (packet.containsKey(STATUS.toString()) && packet.containsValue(ACCEPT.toString())) {
                    // Check if the client requests to use an ID, or if they want it custom.
                    if (packet.containsKey("identify") && packet.containsValue("id")) {
                        client.setIDMode(true);
                        // Check if custom hostname is requested and process.
                        if (packet.containsKey("hostname")) {
                            String hostname = packet.get("hostname");
                            if (hostname != null && !hostname.equals("")) {
                                client.setID(hostname);
                            }
                        }
                    }

                    // If the connection was private, send the Handshake message encrypted after connecting.
                    if (privateMode) {
                        TimeUnit.MILLISECONDS.sleep(250);
                        client.sendMessage(ModifiedPacket.toModified(infoPacket).parseBytes());
                    }

                    // If the Client has accepted, create a new ClientManager instance and add to the list, then
                    // announce the Client has been connected to the ServerListeners.
                    client.resetKeepAlive();
                    NSPServer.clientList.add(client.setThread(new ClientManager(client)).startThread());
                    NSPServer.serverListeners.forEach((listener -> listener.clientConnected(client)));
                    timerRunning[0] = false;

                } else if (packet.containsKey(STATUS.toString()) && packet.containsValue(DISCONNECT.toString())) {
                    client.getSocket().close();
                    timerRunning[0] = false;
                }
            }
            interrupt();
        } catch (IOException e) {
            try {
                // This typically means the Client has forcibly closed the connection without processing first.
                close("disconnected");
            } catch (IOException | GeneralSecurityException ignored) {}
        } catch (GeneralSecurityException | InterruptedException ignored) {}
    }
}

class ModifiedPacket extends Packet {
    /**
     * This is used for creating a new Packet instance with the correct encryption and compression
     * without having to manually set it in a regular instance.
     */
    public ModifiedPacket() {
        AES encryption = NSPServer.option.getEncryption();
        int deflateLevel = NSPServer.option.getDeflateLevel();

        if (encryption != null) { this.setEncryption(encryption); }
        this.setDeflateLevel(deflateLevel);
    }

    public static Packet toModified(Packet packet) {
        AES encryption = NSPServer.option.getEncryption();
        int deflateLevel = NSPServer.option.getDeflateLevel();

        if (encryption != null) { packet.setEncryption(encryption); }
        packet.setDeflateLevel(deflateLevel);

        return packet;
    }

    public Packet toPacket() { return this; }
}

class ConnectionManager extends Thread {
    /**
     * This ConnectionManager is a global Client Manager that monitors if any Client has been removed from the
     * Socket for any reason, such as being kicked, banned, timed out, etc. If so, then the Socket will be properly
     * closed and the Client will be removed from the connection list.
     */
    @Override
    public void run() {
        HashMap<ClientManager, String> queueClose = new HashMap<>();
        while (!isInterrupted()) {
            try {
                // Queues a list of Connections that needs to be removed from the list at the end of looping through
                // every Client, rather than instantly removing to prevent ConcurrentModificationException.
                queueClose.clear();
                NSPServer.clientList.forEach((cli -> {
                    try {
                        ClientManager thread = cli.getThread();

                        if (cli.isBanned()) {
                            ArrayList<String> blackList = NSPServer.option.getBlackList();
                            blackList.add(cli.getIP(false));
                            NSPServer.option.setBlackList(blackList);

                            thread.concurrentClose("banned");
                            queueClose.put(thread, "banned");
                        }
                        if (cli.isKicked()) {
                            thread.concurrentClose("kicked");
                            queueClose.put(thread, "kicked");
                        }
                        if (NSPServer.keepAlive > 0) {
                            if (System.currentTimeMillis() > cli.getKeepAlive()) {
                                thread.concurrentClose("timed out");
                                queueClose.put(thread, "timed out");
                            }
                        }
                    } catch (IOException | GeneralSecurityException ignored) {}
                }));

                // If any clients were queued to be removed from the list, process now.
                queueClose.forEach((cli, reason) -> {
                    NSPServer.clientList.remove(cli.getClient());
                    NSPServer.serverListeners.forEach((listener -> listener.clientDisconnected(cli.getClient(), reason)));
                    cli.interrupt();
                });

                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ignored) {}
        }
    }
}

class SocketAcceptor extends Thread {
    /**
     * The SocketAcceptor is a low-level Thread made to simply wait for any Socket connection be activated, and
     * forwards it to the more complex ConnectionActivator Thread. This is made to free up resources in the Activator
     * and only give it one job and allows for multithreaded connecting.
     */
    @Override
    public void run() {
        while (!isInterrupted()) {
            try {
                Socket socket = NSPServer.server.accept();
                if (socket.isConnected()) {
                    // Only create a new ConnectionActivator is the Socket is still connected.
                    new ConnectionActivator(socket).start();
                }
            } catch (IOException ignored) {}
        }
    }
}