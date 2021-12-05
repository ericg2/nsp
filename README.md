# Next Socket Protocol
NSP is an API that is designed to securely send information using Sockets between 
Multiple Clients. This has many integrated features such as:

* Multiple Client Support and Handling
* Encryption and Compression
* Keep Alive Support
* Custom Packet API
* Optional ID Mode to protect real IP addresses
* Limit Maximum Users, and multiple Socket connections from same IP
* Easy to use features such as Builders and Listeners
* **+ more!**

# Background
I originally designed NSP to be a powerful, easy to use Socket because using only the default
Socket API was not a good option for the types of programs I wanted to create, and having to deal with
making Threads all the time for every program I made was making everything more difficult. This makes it 
significantly easier to integrate **Multiple Client** Sockets into every program I want, such as chats, 
control programs, games, etc. 

# Starting Example
In order to initally create a basic Server and Client, you need to create a `ServerOption` builder, which 
will allow you to specify the options for Server creation. After this, you can need to create a new `NSPServer` 
instance and pass the options to it. After this, you can create a new `NSP` client similar to how the regular 
`Socket` instance is created, however it automatically handshakes to what you put in the constructor.

**Example of Basic Server + Client Communication**

```java
public class ConnectionExample {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        // Initialize a new ServerOptions instance to specify the Options we are going to use.
        ServerOption options = new ServerOption();

        // Create a new NSPServer using the Default Options, and start running.
        NSPServer server = new NSPServer(8080, options).bind();

        // Create a new NSP Client and connect to the Server.
        NSP client = new NSP("127.0.0.1", 8080);
        NSP.HandshakeReader reader = client.connect();
    }
}
```

# Handshake Reading
When you first connect a new Client to a running Server, it sends out a Handshake Packet which will be unparsed
by the `HandshakeReader` class. This will tell everything about the publicly available information based on the 
Server options and what can be determined at the time of connection. 

**Example of Reading Handshake**
```java
public class HandshakeExample {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        // Initialize a new ServerOptions instance to specify the Options we are going to use.
        NSPServer server = new NSPServer(8080, new ServerOption()).bind();

        // Create a new NSP Client and connect to the Server.
        NSP client = new NSP("127.0.0.1", 8080);
        NSP.HandshakeReader reader = client.connect();

        // If this is true, there is an error that prevents the Client from connecting such as whitelisted,
        // blacklisted, bad encryption, etc.
        System.out.println("Errored: " + reader.isError());

        // Loop through all the other Handshake Options by returning the original HashMap
        reader.getHashMap().forEach((key, value) -> System.out.println(key + " = " + value));
    }
}
```

# Other Features
There are many other features available than what was specified above as well to try out. You can check it out
by looking at the JavaDoc or browing through the code! You can find the documentatin either in the `docs` folder,
or at my website: https://houseofkraft.github.io/nsp/docs/

### Android Support
This may be able to easily be converted to Android with none to very little modification, but no support is 
guaranteed, however there may be an Android fork eventually that will have support for this.
