package com.houseofkraft.nsp.networking;

/*
 * Message Handler for Next Socket Protocol
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

import com.houseofkraft.nsp.tool.ThreadTimer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class Messages {
    /**
     * Reads a message from the InputStream, without any form of processing, using a specified Timeout.
     * @param inputStream The InputStream to use for receiving
     * @param timeout Timeout
     * @return Received ByteArray
     */
    private static byte[] readMessageOutput(DataInputStream inputStream, int timeout) throws IOException {
        byte[] output;
        AtomicBoolean loopRunning = new AtomicBoolean(true);

        new ThreadTimer(timeout).addListener(new ThreadTimer.TimerListener() {
            @Override public void timerComplete() { loopRunning.set(false); }
            @Override public void timerError(String errorCode) {}
        }).startTimer();

        do {
            output = inputStream.readUTF().getBytes(StandardCharsets.ISO_8859_1);
        } while (output.length <= 0 && loopRunning.get());
        return output;
    }

    /**
     * Reads a message from the InputStream, without any form of processing.
     * @param inputStream The InputStream to use for receiving
     * @return Received ByteArray
     */
    private static byte[] readMessageOutput(DataInputStream inputStream) throws IOException {
        return readMessageOutput(inputStream, 60);
    }

    /**
     * Reads a message from the InputStream, and processes it to a ByteArray Hashmap using a specified Parser.
     * @param inputStream The InputStream to use for receiving
     * @return Received ByteArray HashMap
     */
    public static HashMap<byte[], byte[]> readMessage(DataInputStream inputStream, PacketParser parser) throws GeneralSecurityException,
            IOException {

        return parser.deflatePacketBytes(readMessageOutput(inputStream));
    }

    /**
     * Reads a message from the InputStream, and processes it to a String Hashmap using a specified Parser and Timeout.
     * @param inputStream The InputStream to use for receiving
     * @param timeout Timeout
     * @return Received String HashMap
     */
    public static HashMap<String, String> readMessageString(DataInputStream inputStream, PacketParser parser, int timeout) throws GeneralSecurityException,
            IOException {

        return parser.deflatePacketString(readMessageOutput(inputStream, timeout));
    }

    /**
     * Reads a message from the InputStream, and processes it to a String Hashmap using a specified Parser.
     * @param inputStream The InputStream to use for receiving
     * @return Received String HashMap
     */
    public static HashMap<String, String> readMessageString(DataInputStream inputStream, PacketParser parser) throws GeneralSecurityException,
            IOException {

        return parser.deflatePacketString(readMessageOutput(inputStream));
    }

    /**
     * Sends a ByteArray message using the OutputStream
     * @param outputStream Socket OutputStream
     * @param bytes ByteArray to Send
     * @return If the message was sent successfully without an exception.
     */
    public static boolean sendMessage(DataOutputStream outputStream, byte[] bytes) {
        try {
            outputStream.writeUTF(new String(bytes, StandardCharsets.ISO_8859_1));
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
