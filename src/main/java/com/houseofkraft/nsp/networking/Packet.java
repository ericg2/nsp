package com.houseofkraft.nsp.networking;

/*
 * Packet Generator for Next Socket Protocol
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.zip.Deflater;

public class Packet {
    private AES cryptHandler;
    private int compressionLevel;
    private HashMap<byte[], byte[]> packetArray;
    private static final byte[] recordSplit = NSPHeader.RECORD_SEPARATOR.toByteArray();
    private static final byte[] groupSplit = NSPHeader.GROUP_SEPARATOR.toByteArray();

    /**
     * Parses the HashMap into a ByteArray using a forEach loop and ByteArrayOutputStream, and will
     * output the key and value, as well as the proper separators into the ByteArray which will be trimmed
     * and returned.
     *
     * @param byteMap ByteArray HashMap
     * @return Parsed ByteArray
     * @throws IOException If there are any errors in the OutputStream.
     */
    private byte[] parseHashMap(HashMap<byte[], byte[]> byteMap) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byteMap.forEach((k,v) -> {
            try {
                bos.write(k);
                bos.write(recordSplit);
                bos.write(v);
                bos.write(groupSplit);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        byte[] output = bos.toByteArray();
        if (output[output.length-1] == NSPHeader.GROUP_SEPARATOR.toByte()) {
            output[output.length-1] = 0;
        }
        bos.close();
        return output;
    }

    /**
     * Adds an Entry to the HashMap using a ByteArray Key and Value
     * @param key ByteArray Key
     * @param value ByteArray Value
     * @return Packet Builder
     */
    public Packet addEntry(byte[] key, byte[] value) { packetArray.put(key, value); return this; }

    /**
     * Adds an Entry to the HashMap using a String Key and Value
     * @param key String Key
     * @param value String Value
     * @return Packet Builder
     */
    public Packet addEntry(String key, String value) { packetArray.put(key.getBytes(), value.getBytes()); return this; }

    /**
     * Removes an Entry from the HashMap
     * @param key Key to Remove
     * @return Packet Builder
     */
    public Packet removeEntry(String key) { packetArray.remove(key.getBytes()); return this; }

    /**
     * Removes the old entry key, and replaces it with the updated value, while keeping the key.
     * @param key Key to Change
     * @param newValue Value to Change
     * @return Packet Builder
     */
    public Packet changeEntry(String key, String newValue) { removeEntry(key).addEntry(key, newValue); return this; }

    /**
     * Sets a custom HashMap ByteArray to replace the existing Packet HashMap.
     * @param customMap Custom ByteArray Hashmap
     * @return Packet Builder
     */
    public Packet setCustomMapByte(HashMap<byte[], byte[]> customMap) { packetArray = customMap; return this; }

    /**
     * Changes the Deflation level for the Parser using the built-in Levels.
     * @param compressionLevel Deflate Level
     * @see Deflater
     * @return Packet Builder
     */
    public Packet setDeflateLevel(int compressionLevel) { this.compressionLevel = compressionLevel; return this; }

    /**
     * Changes the Encryption Handler for the Parser
     * @param handler AES Object
     * @return Packet Builder
     */
    public Packet setEncryption(AES handler) { this.cryptHandler = handler; return this; }

    /**
     * Sets a custom HashMap String to replace the existing Packet HashMap.
     * @param stringMap Custom String HashMap
     * @return Packet Builder
     */
    public Packet setCustomMap(HashMap<String, String> stringMap) {
        packetArray = ByteTools.stringToByteMap(stringMap);
        return this;
    }

    /**
     * Parses the Packet bytes by processing encryption, compression, and ByteArray inflation to form one
     * send-able ByteArray.
     * @return Parsed ByteArray
     * @throws IOException ByteStream Error
     * @throws GeneralSecurityException Encryption Error
     */
    public byte[] parseBytes() throws IOException, GeneralSecurityException {

        byte[] inflatedMap = this.parseHashMap(this.packetArray);
        if (compressionLevel != Deflater.NO_COMPRESSION) { inflatedMap = ByteTools.inflateBytes(inflatedMap, compressionLevel); }
        if (cryptHandler != null) { inflatedMap = this.cryptHandler.encryptBytes(inflatedMap); }

        return inflatedMap;
    }

    /**
     * @return Packet Parser
     */
    public PacketParser getParser() {
        PacketParser parser = new PacketParser();
        parser.setDeflate(compressionLevel != Deflater.NO_COMPRESSION);
        if (cryptHandler != null) parser.setEncryption(cryptHandler);
        return parser;
    }

    public Packet() { this.packetArray = new HashMap<>(); }
}
