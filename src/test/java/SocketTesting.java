/*
 * Next Socket Protocol Tester
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

import com.houseofkraft.nsp.networking.NSPServer;
import com.houseofkraft.nsp.encryption.*;
import com.houseofkraft.nsp.listener.ServerListener;
import com.houseofkraft.nsp.networking.Client;
import com.houseofkraft.nsp.networking.NSP;
import com.houseofkraft.nsp.networking.Packet;
import com.houseofkraft.nsp.networking.ServerOption;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.Deflater;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SocketTesting {
    protected final int testAmount = 150;
    private void getMemory() {
        long afterMem = Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
        long totalUsed = afterMem-GlobalVariables.beforeMem;

        System.out.println("Total Memory Used > " + totalUsed/1000000 + " MB");
    }

    @Test
    @DisplayName("Initialize Server")
    @Order(0)
    public void A_initServer_A() throws IOException, GeneralSecurityException {
        GlobalVariables.beforeMem = Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
        GlobalVariables.aesOption = new AESOption()
                .setAlgorithm(Algorithm.CBC)
                .setShaType(SHAType.SHA_512)
                .setKeyType(KeyType.AES_256)
                .setKeyPassword("Hello", "World");

        GlobalVariables.aes = new AES(GlobalVariables.aesOption);
        GlobalVariables.serverOption = new ServerOption()
                .setEncryption(GlobalVariables.aes)
                .setDeflateLevel(Deflater.BEST_COMPRESSION)
                .setKeepAlive(20)
                .setDiscloseClients(true);

        GlobalVariables.server = new NSPServer(8080, GlobalVariables.serverOption).bind();
        Assertions.assertTrue(GlobalVariables.server.isRunning());

        GlobalVariables.server.addListener(new ServerListener() {
            @Override public void messageReceived(Client client, HashMap<String, String> packet) {
                GlobalVariables.messageReceived++;
                GlobalVariables.receivedMessages.add(packet);
                System.out.println(GlobalVariables.messageReceived + " messages received");
            }
            @Override public void clientConnected(Client client) {
                GlobalVariables.clientConnected++;
                System.out.println(GlobalVariables.clientConnected + " connected (" + client.getIdentifier(true) + ")");
            }
            @Override public void clientDisconnected(Client client, String reason) {
                GlobalVariables.clientDisconnected++;
                GlobalVariables.clientConnected--;
                System.out.println(GlobalVariables.clientDisconnected + " disconnected due to " + reason);
            }
            
            @Override public void serverDisconnected() {}
            @Override public void serverConnected() {}
        });
    }

    @Test
    @DisplayName("Mass Connection Test")
    @Order(1)
    public void B_massConnection_B() throws GeneralSecurityException, IOException, InterruptedException {
        System.out.println("> Testing Mass Connections... (" + testAmount + ")");

        // Connect the specified amount of clients rapidly in a short amount of time, and checking if all of these
        // client connections are retained.
        for (int i=0; i<testAmount; i++) {
            NSP client = new NSP("192.168.1.149", 8080)
                    .setEncryption(GlobalVariables.aes)
                    .setDeflateLevel(Deflater.BEST_COMPRESSION);
            client.connect();
            GlobalVariables.clientList.add(client);
            TimeUnit.MILLISECONDS.sleep(75);
        }
        getMemory();
        Assertions.assertEquals(GlobalVariables.clientConnected, testAmount);
    }

    @Test
    @DisplayName("Mass Message Test")
    @Order(2)
    public void C_messageTest_C() {
        System.out.println("> Testing Message Integrity & Losses...");

        // Send the message many times based on the testing amount, and have each Packet contain 5 entries with
        // all randomized to test packet losses and potential corruption.
        for (int i=0; i<3; i++) {
            GlobalVariables.clientList.forEach(cli -> {
                try {
                    HashMap<String, String> packet = new HashMap<>();
                    for (int j=0; j<5; j++) {
                        packet.put(AES.generatePassword(8), AES.generatePassword(8));
                    }
                    cli.broadcast(
                            new Packet()
                                    .setEncryption(GlobalVariables.aes)
                                    .setDeflateLevel(Deflater.BEST_COMPRESSION)
                                    .setCustomMap(packet)
                    );
                    GlobalVariables.sentMessages.add(packet);
                    TimeUnit.MILLISECONDS.sleep(10);
                } catch (Exception ignored) {}
            });
        }

        // Check if the sending ArrayList and received ArrayList match up completely, if they do then there is zero
        // packet loss or corruption.
        getMemory();
        Assertions.assertEquals(GlobalVariables.sentMessages, GlobalVariables.receivedMessages);
    }

    @Test
    @DisplayName("Hostname")
    @Order(3)
    public void E_hostname_E() throws GeneralSecurityException, IOException {
        System.out.println("> Testing Hostname and ID changes...");

        // Use the first connected Client to change the hostname, and see if it registers correctly.
        String hostname = AES.generatePassword(64);
        GlobalVariables.clientList.get(0).setHostname(hostname);

        String serverHostname = GlobalVariables.server.getClients(hostname, false).get(0).getIdentifier(false);

        System.out.println("> Server hostname is " + serverHostname + ", expected: " + hostname);
        getMemory();
        Assertions.assertEquals(hostname, serverHostname);
    }

    @Test
    @DisplayName("Kick Test")
    @Order(4)
    public void F_kickTest_F() throws InterruptedException {
        System.out.println("> Kicking 50 clients...");
        AtomicInteger counter = new AtomicInteger(0);
        GlobalVariables.server.getClientList().forEach(cli -> {
            try {
                if (counter.get() < 50) {
                    cli.kick();
                    counter.set(counter.get() + 1);
                    TimeUnit.MILLISECONDS.sleep(100);
                }
            } catch (Exception ignored) {}
        });

        TimeUnit.SECONDS.sleep(2);
        getMemory();
        Assertions.assertEquals(testAmount-50, GlobalVariables.clientConnected);
    }

    @Test
    @DisplayName("Ban Test")
    @Order(5)
    public void G_banTest_G() throws InterruptedException {
        System.out.println("> Banning 50 clients...");

        AtomicInteger counter = new AtomicInteger(0);
        GlobalVariables.server.getClientList().forEach(cli -> {
            try {
                if (counter.get() < 50) {
                    cli.ban();
                    counter.set(counter.get() + 1);
                    TimeUnit.MILLISECONDS.sleep(100);
                }
            } catch (Exception ignored) {}
        });

        TimeUnit.SECONDS.sleep(2);
        getMemory();
        Assertions.assertEquals(50, GlobalVariables.server.getOptions().getBlackList().size());
    }

    @Test
    @DisplayName("Server Close")
    @Order(6)
    public void I_serverClose_I() throws IOException {
        System.out.println("> Closing Server...");
        GlobalVariables.server.close();
        getMemory();
        System.out.println("> Running Garbage Cleanup...");
        System.gc();
        getMemory();
        Assertions.assertFalse(GlobalVariables.server.isRunning());
    }
}

class GlobalVariables {
    protected static NSPServer server;
    protected static ServerOption serverOption;
    protected static AESOption aesOption;
    protected static AES aes;
    protected static long beforeMem;
    protected static final ArrayList<NSP> clientList = new ArrayList<>();
    protected static final ArrayList<HashMap<String, String>> receivedMessages = new ArrayList<>();
    protected static final ArrayList<HashMap<String, String>> sentMessages = new ArrayList<>();
    protected static int messageReceived = 0, clientConnected = 0, clientDisconnected = 0;
}