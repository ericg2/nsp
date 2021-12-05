package com.houseofkraft.nsp.encryption;

/*
 * SHA Type for AES Encryption
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

public enum SHAType {
    /** SHA-1 Hashing */
    SHA_1(1),

    /** SHA-256 Hashing*/
    SHA_256(256),

    /** SHA-384 Hashing */
    SHA_384(384),

    /** SHA-512 Hashing */
    SHA_512(512);

    /** Stored SHA Size */
    private final int shaSize;

    /** @return SHA Hashing Size */
    public int size() { return this.shaSize; }

    /**
     * Creates a specified SHA Size and Name.
     * @param shaSize SHA Size
     */
    SHAType(int shaSize) {
        this.shaSize = shaSize;
    }
}
