package com.houseofkraft.nsp.networking;

/*
 * Headers Enum for Next Socket Protocol
 * Copyright (c) 2022 houseofkraft
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.houseofkraft.nsp.tool.ByteTools;

import java.nio.charset.StandardCharsets;

/**
 * This is used to form a dictionary of Unicode Characters that can be converted to bytes,
 * strings, or other types which can be sent through the socket, telling what was
 * intended. These sequences mostly follow the standards, with some exceptions being custom
 * messages such as telling the handler about possible encryption, compression, size, etc.
 *
 * @see <a href="http://www.asciitable.com/index/asciifull.gif">HTML Hexadecimal Sequence</a>
 */

public enum NSPHeader {
    /** Used for Starting a Socket Transmission Message **/
    START_OF_HEADING(0x0001),

    /** Used for Starting Text, like a KeyFile **/
    START_OF_TEXT(0x0002),

    /** Used for Ending a Socket Transmission Message **/
    END_OF_TRANSMISSION(0x0004),

    /** Used for Secure Packet **/
    NETWORK_PACKET(0x0005),

    GROUP_SEPARATOR(0x001D),
    RECORD_SEPARATOR(0x001E);

    private final int unicodeHex;
    NSPHeader(int unicodeHex) { this.unicodeHex = unicodeHex; }

    public byte toByte() { return (byte)this.unicodeHex; }
    public byte[] toByteArray() { return ByteTools.intToBytes(this.unicodeHex); }
    public int toInt() { return this.unicodeHex; }

    enum Message {
        STATUS("nsp-status"),
        ACCEPT("accept"),
        DENY("nsp-cancel"),
        REASON("reason"),
        DISCONNECT("disconnect"),
        TYPE("nsp-type"),
        PRIVATE("private");

        private final String socketMessage;
        Message(String socketMessage) { this.socketMessage = socketMessage; }

        @Override
        public String toString() { return this.socketMessage; }
        public byte[] toByteArray() { return socketMessage.getBytes(StandardCharsets.UTF_8); }
    }
}
