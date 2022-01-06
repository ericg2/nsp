package com.houseofkraft.nsp.networking;

/*
 * Client Manager for Next Socket Protocol
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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class ClientManager extends Thread {
    private final Client client;

    /** @return Client */
    public Client getClient() { return this.client; }

    /**
     * Closes the Socket concurrently, without interfering with the automatic scan process.
     * @param reason Close Reason
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     */
    public void concurrentClose(String reason) throws IOException, GeneralSecurityException {
        this.client.sendMessage(
                new Packet()
                        .addEntry(NSPHeader.Message.STATUS.toString(), NSPHeader.Message.DISCONNECT.toString())
                        .addEntry("reason", reason)
                        .parseBytes()
        );
        this.client.getSocket().close();
    }

    /**
     * Closes the Socket while removing from the Client List, and announce to Listeners.
     * @param reason Close Reason
     * @throws GeneralSecurityException If there is an encryption error.
     * @throws IOException If there is a socket error.
     */
    public void close(String reason) throws IOException, GeneralSecurityException {
        concurrentClose(reason);
        NSPServer.clientList.remove(client);
        NSPServer.serverListeners.forEach((listener -> listener.clientDisconnected(client, reason)));
        interrupt();
    }

    @Override
    public void run() {
        while (!isInterrupted() && !client.getSocket().isClosed()) {
            try {
                HashMap<String, String> packet = client.readMessageString(NSPServer.parser);
                if (packet != null && !packet.isEmpty()) {
                    client.resetKeepAlive();
                    Packet response = new ModifiedPacket().toPacket();
                    boolean privateMessage = false;

                    if (packet.containsKey(NSPHeader.Message.STATUS.toString())) {
                        switch (packet.get(NSPHeader.Message.STATUS.toString())) {
                            case "disconnect" -> close(NSPHeader.Message.DISCONNECT.toString());
                            case "client-list" -> {
                                if (NSPServer.option.getDiscloseClientList()) {
                                    // Send the Preferred Client List
                                    AtomicInteger counter = new AtomicInteger(0);
                                    NSPServer.getConnectedList().forEach((cli -> {
                                        response.addEntry("cli-" + counter, cli);
                                        counter.set(counter.get() + 1);
                                    }));
                                    response.addEntry(NSPHeader.Message.STATUS.toString(), "client-list-success")
                                            .addEntry("identifier", "system");
                                } else {
                                    response.addEntry(NSPHeader.Message.STATUS.toString(), "client-list-fail")
                                            .addEntry("identifier", "system");
                                }
                            }
                            case "hostname" -> {
                                // Check to see if there is another Packet entry for the hostname value.
                                String newHostname = packet.get("hostname");
                                if (!newHostname.equals("")) {
                                    // Change the hostname, and set the preferred ID to hostname mode if not done already.
                                    client.setIDMode(true);
                                    client.setID(newHostname);

                                    response.addEntry(NSPHeader.Message.STATUS.toString(), "hostname-change-success")
                                            .addEntry("identifier", "system");
                                }
                            }

                            case "id-mode" -> {
                                // Set the Preferred ID to Hostname Mode
                                client.setIDMode(true);
                                response.addEntry(NSPHeader.Message.STATUS.toString(), "id-change-success")
                                        .addEntry("identifier", "system");
                            }

                            case "ip-mode" -> {
                                client.setIDMode(false);
                                response.addEntry(NSPHeader.Message.STATUS.toString(), "ip-change-success")
                                        .addEntry("identifier", "system");
                            }

                            case "get-id" -> response.addEntry(NSPHeader.Message.STATUS.toString(), "id-request-success")
                                    .addEntry("identifier", "system")
                                    .addEntry("id", client.getID());

                            case "keep-alive" -> response.addEntry(NSPHeader.Message.STATUS.toString(), "keep-alive-success")
                                    .addEntry("identifier", "system");
                        }
                    } else if (packet.containsKey("ssnp-sender")) {
                        // Attempt to look up the preferred identifier of the Client.
                        ArrayList<Client> clientList = NSPServer.getClientStatic(packet.get("ssnp-sender"), true);

                        if (clientList.size() > 0) {
                            response.addEntry("identifier", client.getIdentifier(true));
                            privateMessage = true;
                            packet.forEach(response::addEntry);

                            clientList.forEach((cli -> {
                                try {
                                    cli.sendMessage(response.parseBytes());
                                } catch (Exception ignored) {
                                }
                            }));
                        }
                    } else {
                        packet.forEach(response::addEntry);
                        response.addEntry("identifier", client.getIdentifier(true));
                        NSPServer.serverListeners.forEach(li -> li.messageReceived(client, packet));
                    }
                    if (!privateMessage) {
                        client.sendMessage(response.parseBytes());
                    }
                }
            } catch (IOException io) {
                try {
                    if (!client.getSocket().isClosed()) {
                        close("disconnected");
                    }
                } catch (Exception ignored) {}
            } catch (GeneralSecurityException ignored) {}
        }
    }

    public ClientManager(Client client) {
        this.client = client;
    }
}
