package com.houseofkraft.nsp.encryption;

/*
 * Key Type for AES Encryption
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

public enum KeyType {
    /** AES-128 Key */
    AES_128(128),

    /** AES-192 Key */
    AES_192(192),

    /** AES-256 Key */
    AES_256(256);

    /** Stored Key Size */
    private final int keySize;

    /** @return Key Size Int */
    public int size() { return this.keySize; }

    /**
     * Creates a specified Key Size and Name.
     * @param keySize Key Size
     */
    KeyType(int keySize) {
        this.keySize = keySize;
    }
}
