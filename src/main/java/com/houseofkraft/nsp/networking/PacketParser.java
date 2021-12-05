package com.houseofkraft.nsp.networking;

/*
 * Packet Parser for Next Socket Protocol
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
import com.houseofkraft.nsp.tool.ByteTools;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;

public class PacketParser {
    private static final byte[] recordSplit = NSPHeader.RECORD_SEPARATOR.toByteArray();
    private static final byte[] groupSplit = NSPHeader.GROUP_SEPARATOR.toByteArray();
    private boolean deflateEnabled = false;
    private AES cryptHandler;

    private HashMap<byte[], byte[]> deflateHashMap(byte[] parsedMap) {
        HashMap<byte[], byte[]> output = new HashMap<>();
        for (byte[] key: ByteTools.tokens(parsedMap, groupSplit)) {
            if (ByteTools.containsByte(key, NSPHeader.RECORD_SEPARATOR.toByte()) > 0) {
                List<byte[]> keyPairs = ByteTools.tokens(ByteTools.trim(key), recordSplit);
                output.put(keyPairs.get(0), keyPairs.get(1));
            }
        }
        return output;
    }

    private HashMap<String, String> deflateHashMapString(byte[] parsedMap) {
        HashMap<String, String> output = new HashMap<>();
        for (byte[] key: ByteTools.tokens(parsedMap, groupSplit)) {
            if (ByteTools.containsByte(key, NSPHeader.RECORD_SEPARATOR.toByte()) > 0) {
                List<byte[]> keyPairs = ByteTools.tokens(ByteTools.trim(key), recordSplit);
                output.put(new String(keyPairs.get(0)), new String(keyPairs.get(1)));
            }
        }
        return output;
    }

    public PacketParser setEncryption(AES handler) { this.cryptHandler = handler; return this; }
    public PacketParser setDeflate(boolean deflateEnabled) { this.deflateEnabled = deflateEnabled; return this; }

    public HashMap<byte[], byte[]> deflatePacketBytes(byte[] parsedBytes) throws IOException,
            GeneralSecurityException {

        byte[] bytes = parsedBytes;
        if (this.cryptHandler != null) {
            bytes = this.cryptHandler.decryptBytes(bytes);
        }
        if (this.deflateEnabled) { bytes = ByteTools.deflateBytes(bytes); }
        return deflateHashMap(bytes);
    }

    public HashMap<String, String> deflatePacketString(byte[] parsedBytes) throws IOException,
            GeneralSecurityException {

        byte[] bytes = parsedBytes;
        if (this.cryptHandler != null) { bytes = this.cryptHandler.decryptBytes(bytes); }
        if (this.deflateEnabled) { bytes = ByteTools.deflateBytes(bytes); }
        return deflateHashMapString(bytes);
    }

    public PacketParser() {}
}