package com.houseofkraft.nsp.listener;

/*
 * Server Listener for Next Socket Protocol
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

import com.houseofkraft.nsp.networking.Client;
import java.util.HashMap;

public interface ServerListener {
    /**
     * This event is called when a message is received from any of the clients automatically.
     *
     * @param client Received Client Object
     * @param packet Received ByteArray Packet
     */
    void messageReceived(Client client, HashMap<String, String> packet);

    /**
     * This event is called when a new Client is connected to the Socket.
     *
     * @param client Connected Client Object
     */
    void clientConnected(Client client);

    /**
     * This event is called when a Client is disconnected from the Socket.
     *
     * @param client Disconnected Client Object
     * @param reason Reason for Disconnection
     */
    void clientDisconnected(Client client, String reason);

    /**
     * This event is called when the server has been shut off for any reason.
     */
    void serverDisconnected();
}
