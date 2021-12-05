package com.houseofkraft.nsp.tool;

/*
 * Byte Tools for Next Socket Protocol
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


public class ByteTools {
    /**
     * Splits a ByteArray using a delimiter into multiple lists, very similar to the
     * normal split tool for a String. This is based off a solution from StackOverFlow that was modified
     * slightly to fit the usage of this program.
     *
     * @param array ByteArray to parse for splitting
     * @param delimiter ByteArray to use for separator
     * @see <a href="https://stackoverflow.com/q/22519346/">Question</a>
     * @return Parsed Bytes List
     */
    public static List<byte[]> tokens(byte[] array, byte[] delimiter) {
        List<byte[]> byteArrays = new LinkedList<>();
        if (delimiter.length == 0) {
            return byteArrays;
        }
        int begin = 0;

        outer:
        for (int i = 0; i < array.length - delimiter.length + 1; i++) {
            for (int j = 0; j < delimiter.length; j++) {
                if (array[i + j] != delimiter[j]) {
                    continue outer;
                }
            }
            byteArrays.add(Arrays.copyOfRange(array, begin, i));
            begin = i + delimiter.length;
        }
        byteArrays.add(Arrays.copyOfRange(array, begin, array.length));
        return byteArrays;
    }

    /**
     * Checks if a ByteArray contains a certain Byte, mostly used for splitting and finding Group and
     * Record Separators.
     *
     * @param array ByteArray to Scan
     * @param delimiter Byte to Search For
     * @return How many times (if any) the Byte was found in the input ByteArray
     */
    public static int containsByte(byte[] array, byte delimiter) {
        int foundTimes = 0;
        for (int i = 0; i < array.length - 1; i++) {
            if (array[i] == delimiter) foundTimes++;
        }
        return foundTimes;
    }

    /**
     * Removes any zero's from the ByteArray, used for certain functions.
     * @param bytes ByteArray to Scan
     * @return Trimmed ByteArray
     */
    public static byte[] trim(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            --i;
        }
        return Arrays.copyOf(bytes, i + 1);
    }

    /**
     * Uses the Compression Stream combined with a custom Deflate Level to compress a ByteArray.
     * @param plainBytes Plain ByteArray
     * @param compressLevel Compression Level
     * @return Compressed ByteArray
     * @throws IOException If there are any problems in any InputStream/OutputStream.
     */
    public static byte[] inflateBytes(byte[] plainBytes, int compressLevel) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(plainBytes);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPOutputStream inflateStream = new GZIPOutputStream(bos, compressLevel);

        int data;
        while ((data = bis.read())!=-1) {
            inflateStream.write(data);
        }
        inflateStream.finish();
        byte[] outputByte = bos.toByteArray();

        bis.close();
        bos.close();
        inflateStream.close();
        return outputByte;
    }

    /**
     * Decompresses a ByteArray into one in a regular format and length.
     * @param inflatedBytes Inflated ByteArray
     * @return Deflated ByteArray
     * @throws IOException If there are any problems in any InputStream/OutputStream.
     */
    public static byte[] deflateBytes(byte[] inflatedBytes) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(inflatedBytes);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        GZIPInputStream deflateStream = new GZIPInputStream(bis);

        int data;
        while ((data = deflateStream.read())!=-1) {
            bos.write(data);
        }
        byte[] outputByte = bos.toByteArray();

        bis.close();
        bos.close();
        deflateStream.close();
        return outputByte;
    }

    /**
     * Converts a String HashMap into a ByteArray HashMap
     * @param stringMap String HashMap
     * @return ByteArray HashMap
     */
    public static HashMap<byte[], byte[]> stringToByteMap(HashMap<String, String> stringMap) {
        HashMap<byte[], byte[]> output = new HashMap<>();
        stringMap.forEach((k,v) -> output.put(k.getBytes(), v.getBytes()));
        return output;
    }

    /**
     * Converts an Integer or Byte into a ByteArray
     * @param convertInt Integer to Convert
     * @return ByteArray containing Integer
     */
    public static byte[] intToBytes(final int convertInt) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(convertInt);
        return bb.array();
    }

    /** Constructor for ByteTools **/
    public ByteTools() {}
}