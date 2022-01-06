package com.houseofkraft.nsp.encryption;

/*
 * Algorithm for AES Encryption
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

public enum Algorithm {
    /** CBC Algorithm */
    CBC("CBC"),

    /** GCM Algorithm */
    GCM("GCM");

    /** Stored Algorithm Name */
    public final String algoName;

    /** @return Algorithm String Name */
    public String getAlgorithmName() { return algoName; }

    /**
     * Creates a new Algorithm with a specified name.
     * @param algo Algorithm Name
     */
    Algorithm(String algo) {
        algoName = algo;
    }
}
