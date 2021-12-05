package com.houseofkraft.nsp.encryption;

/*
 * AES Options for Next Socket Protocol
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

import com.houseofkraft.nsp.networking.NSPHeader;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class AESOption {
    private boolean autoGenerated = true;

    private SecretKey privateKey;
    private IvParameterSpec iv;

    private KeyType keyType = KeyType.AES_256;
    private SHAType shaType = SHAType.SHA_256;
    private Algorithm algorithm = Algorithm.CBC;
    private int iteration = 65536;

    private String keyFileLocation;
    private File keyFileObject;
    private String keyPassword;
    private String keySalt;

    /** @return Auto-Generated */
    public boolean isAutoGenerated() { return autoGenerated; }
    public AESOption setAutoGenerated(boolean autoGenerated) { this.autoGenerated = autoGenerated; return this; }

    /** @return Private Key */
    public SecretKey getPrivateKey() { return privateKey; }

    /** Sets the Private Key */
    public AESOption setPrivateKey(SecretKey privateKey) { this.privateKey = privateKey; return this; }

    /** @return IV */
    public IvParameterSpec getIv() { return iv; }

    /** Sets the IV */
    public AESOption setIv(IvParameterSpec iv) { this.iv = iv; return this; }

    /** @return Key File Location */
    public String getKeyFileLocation() { return keyFileLocation; }

    /** Sets the Key File Location */
    public AESOption setKeyFileLocation(String keyFileLocation) { this.keyFileLocation = keyFileLocation; return this; }

    /** @return Key File Object */
    public File getKeyFileObject() { return keyFileObject; }

    /** Sets the Key File Object */
    public AESOption setKeyFileObject(File keyFileObject) { this.keyFileObject = keyFileObject; return this; }

    /** @return Key Password */
    public String getKeyPassword() { return keyPassword; }

    /** Sets the Key Password */
    public AESOption setKeyPassword(String keyPassword) { this.keyPassword = keyPassword; return this; }

    /** @return Key Salt */
    public String getKeySalt() { return keySalt; }

    /** Sets the Key Salt */
    public AESOption setKeySalt(String keySalt) { this.keySalt = keySalt; return this; }

    /** @return Key Type */
    public KeyType getKeyType() { return keyType; }

    /** Sets the Key Type */
    public AESOption setKeyType(KeyType keyType) { this.keyType = keyType; return this; }

    /** @return SHA Type */
    public SHAType getShaType() { return shaType; }

    /** Sets the SHA Type */
    public AESOption setShaType(SHAType shaType) { this.shaType = shaType; return this; }

    /** @return Encryption Algorithm */
    public Algorithm getAlgorithm() { return algorithm; }

    /** Sets the Algorithm */
    public AESOption setAlgorithm(Algorithm algorithm) { this.algorithm = algorithm; return this; }

    /** @return Encryption Iteration Count */
    public int getIteration() { return iteration; }

    /** Sets the Iteration Count */
    public AESOption setIteration(int iteration) { this.iteration = iteration; return this; }

    /**
     * Changes the Key based on the Password and Salt. If there is no salt used, the salt will be the same
     * as the password.
     *
     * @param password Password
     * @param salt Salt
     * @return AESOption Builder
     */
    public AESOption setKeyPassword(String password, String salt) {
        this.keyPassword = password;
        if (salt.equals("")) {
            this.keySalt = password;
        } else { this.keySalt = salt; }
        return this;
    }

    /**
     * Reads the Key File Object by creating a FileInputStream and using the Array Copying Methods.
     * @param fileObject Key File Object
     * @return If the operation was successful.
     * @throws IOException If there was an issue reading the file.
     */
    private boolean readKeyFile(File fileObject) throws IOException {
        FileInputStream fis = new FileInputStream(fileObject);
        
        byte[] keyFileBytes = fis.readAllBytes();
        byte recordSeparator = NSPHeader.RECORD_SEPARATOR.toByte();
        byte groupSeparator = NSPHeader.GROUP_SEPARATOR.toByte();
        int privateKeyStart = -1;
        int privateKeyEnd = -1;
        int index = 0;

        fis.close();
        for (byte b: keyFileBytes) {
            if (b == recordSeparator) privateKeyStart = index + 1;
            if (b == groupSeparator) privateKeyEnd = index - 1;
            index++;
        }

        if (privateKeyStart > -1 && privateKeyEnd > -1) {
            String algorithm = new String(Arrays.copyOfRange(keyFileBytes, 0, privateKeyStart - 1));
            this.privateKey = new SecretKeySpec(Arrays.copyOfRange(keyFileBytes, privateKeyStart, privateKeyEnd), algorithm);
            this.iv = new IvParameterSpec(Arrays.copyOfRange(keyFileBytes, privateKeyEnd + 2, keyFileBytes.length));
            return true;
        } else { return false; }
    }

    /**
     * Verifies if the entered AES Options would be correct and work without issues when being used.
     * @return If verification is successful.
     * @throws IOException If there is a problem with I/O.
     */
    public boolean verify() throws IOException {
        if (!autoGenerated) {
            if (privateKey == null) {
                if (keyFileObject != null && keyFileObject.isFile()) {
                    readKeyFile(keyFileObject);
                    return true;
                } else if (keyFileLocation != null) {
                    readKeyFile(new File(keyFileLocation));
                    return true;
                } else return false;
            } else return false;
        } else {
            if (keyPassword == null || keyPassword.equals("")) keyPassword = AES.generatePassword(8);
            if (keySalt == null || keySalt.equals("")) keySalt = keyPassword;
            return true;
        }
    }

    /** @return Built AES Object */
    public AES build() throws IOException, GeneralSecurityException {
        return new AES(this);
    }
}