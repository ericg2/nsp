package com.houseofkraft.nsp.networking;

/*
 * Server Options for Next Socket Protocol
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

import java.util.ArrayList;
import java.util.zip.Deflater;

public class ServerOption {
    private int maxUsers = -1;
    private int maxConcurrent = -1;
    private int port = 8080;
    private int handshakeTimeout = 60;
    private int deflateLevel = Deflater.NO_COMPRESSION;
    private int keepAliveTimeout = 60;

    private boolean announceClientActions = true;
    private boolean discloseClients = true;
    private boolean hideAllIP = false;

    private AES encryption = null;
    private ArrayList<String> whiteList = new ArrayList<>();
    private ArrayList<String> blackList = new ArrayList<>();

    /** @return Disclose Client List */
    public boolean getDiscloseClientList() { return discloseClients; }

    /** Sets Disclose Clients */
    public ServerOption setDiscloseClients(boolean discloseClientList) { this.discloseClients = discloseClientList; return this; }

    /** @return Hide All IP Address By Default */
    public boolean isHideAllIP() { return hideAllIP; }

    /** Sets Hide All IP Addresses by Default */
    public ServerOption setHideAllIP(boolean hideAllIP) { this.hideAllIP = hideAllIP; return this; }

    /** @return Announce Client Actions */
    public boolean getAnnounceClientActions() { return this.announceClientActions; }

    /** Sets Announce Client Actions such as Connection, Disconnection, etc. */
    public ServerOption setAnnounceClientActions(boolean announce) { this.announceClientActions = announce; return this; }

    /** @return Max Users */
    public int getMaxUsers() { return maxUsers; }

    /** @return Keep-Alive Timeout in Seconds */
    public int getKeepAlive() { return this.keepAliveTimeout; }

    /** Sets Keep Alive */
    public ServerOption setKeepAlive(int timeout) { this.keepAliveTimeout = timeout; return this; }

    /** Sets Maximum Users For Connecting */
    public ServerOption setMaxUsers(int maxUsers) { this.maxUsers = maxUsers; return this; }

    /** @return Max Concurrent Connections */
    public int getMaxConcurrent() { return maxConcurrent; }

    /** Sets Maximum Connections from one specific IP address */
    public ServerOption setMaxConcurrent(int maxConcurrent) { this.maxConcurrent = maxConcurrent; return this; }

    /** @return Server Port */
    public int getPort() { return port; }

    /** Sets Server Port */
    public ServerOption setPort(int port) { this.port = port; return this; }

    /** @return Deflation Level */
    public int getDeflateLevel() { return deflateLevel; }

    /** Sets Deflate Level */
    public ServerOption setDeflateLevel(int deflateLevel) { this.deflateLevel = deflateLevel; return this; }

    /** @return Encryption Object */
    public AES getEncryption() { return encryption; }

    /** Sets Encryption Object */
    public ServerOption setEncryption(AES encryption) { this.encryption = encryption; return this; }

    /** @return Whitelist */
    public ArrayList<String> getWhiteList() { return whiteList; }

    /** Sets Whitelist */
    public ServerOption setWhiteList(ArrayList<String> whiteList) { this.whiteList = whiteList; return this; }

    /** @return Blacklist */
    public ArrayList<String> getBlackList() { return blackList; }

    /** @return Handshake Timeout */
    public int getHandshakeTimeout() { return handshakeTimeout; }

    /** Sets Handshake Timeout */
    public ServerOption setHandshakeTimeout(int timeout) { this.handshakeTimeout = timeout; return this; }

    /** Sets Blacklist */
    public ServerOption setBlackList(ArrayList<String> blackList) { this.blackList = blackList; return this; }
    public ServerOption() {}
}
