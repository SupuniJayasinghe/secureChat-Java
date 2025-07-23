import utils.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Scanner;

public class Server {
    public static void main(String[] args) throws Exception {
        Auth.registerUser("userA", "pass123"); // optional default user

        ServerSocket serverSocket = new ServerSocket(5000);
        System.out.println("[SERVER] Listening on port 5000...");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new ClientHandler(clientSocket)).start();
        }
    }
}

class ClientHandler implements Runnable {
    private Socket socket;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                Scanner consoleScanner = new Scanner(System.in);) {
            String action = in.readLine();

            if ("REGISTER".equalsIgnoreCase(action)) {
                String username = in.readLine();
                String password = in.readLine();

                boolean registered = Auth.registerUser(username, password);
                out.println(registered ? "REGISTER_SUCCESS" : "REGISTER_FAIL");
                socket.close();
                return;
            }

            if (!"LOGIN".equalsIgnoreCase(action)) {
                out.println("UNKNOWN_COMMAND");
                socket.close();
                return;
            }

            String username = in.readLine();
            String password = in.readLine();

            if (!Auth.authenticate(username, password)) {
                out.println("AUTH_FAIL");
                socket.close();
                return;
            }
            out.println("AUTH_SUCCESS");

            KeyPair rsaKeys = Crypto.generateRSAKeyPair();
            PrivateKey privateKey = rsaKeys.getPrivate();
            PublicKey publicKey = rsaKeys.getPublic();

            out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            String encryptedAESKey = in.readLine();
            byte[] aesKeyBytes = Crypto.decryptRSA(encryptedAESKey, privateKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            System.out.println("[SERVER] Secure chat started with user: " + username);

            // Formatter for timestamps
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            // Thread to read incoming messages from client
            Thread readThread = new Thread(() -> {
                try {
                    while (!socket.isClosed()) {
                        String ivStr = in.readLine();
                        if (ivStr == null)
                            break;

                        String encryptedMsg = in.readLine();
                        if (encryptedMsg == null)
                            break;

                        System.out.println("\n--- Encrypted Message Received ---");
                        System.out.println(encryptedMsg);

                        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivStr));
                        String decryptedMsg = Crypto.decryptAES(encryptedMsg, aesKey, iv);

                        System.out.println(
                                "[" + dtf.format(LocalDateTime.now()) + "] [Client Decrypted]: " + decryptedMsg);
                        System.out.println("-------------------------------\n");

                        if ("bye".equalsIgnoreCase(decryptedMsg.trim())) {
                            System.out.println("[SERVER] Client ended the chat.");
                            socket.close();
                            break;
                        }
                    }

                } catch (Exception e) {
                    if (!socket.isClosed())
                        System.out.println("[SERVER] Read thread error: " + e.getMessage());
                }
            });

            // Thread to send messages to client
            Thread writeThread = new Thread(() -> {
                try {
                    while (!socket.isClosed()) {
                        System.out.print("[Server] Enter message: ");
                        String msgToSend = consoleScanner.nextLine();

                        IvParameterSpec iv = Crypto.generateIV();
                        String ivStr = Base64.getEncoder().encodeToString(iv.getIV());
                        String encryptedMsg = Crypto.encryptAES(msgToSend, aesKey, iv);

                        out.println(ivStr);
                        out.println(encryptedMsg);

                        System.out.println("[" + dtf.format(LocalDateTime.now()) + "] [Server sent encrypted message]");

                        if ("bye".equalsIgnoreCase(msgToSend.trim())) {
                            System.out.println("[SERVER] You ended the chat.");
                            socket.close();
                            break;
                        }
                    }
                } catch (Exception e) {
                    if (!socket.isClosed())
                        System.out.println("[SERVER] Write thread error: " + e.getMessage());
                }
            });

            readThread.start();
            writeThread.start();

            readThread.join();
            writeThread.join();

            System.out.println("[SERVER] Connection closed.");

        } catch (Exception e) {
            System.out.println("[SERVER] Error: " + e.getMessage());
        }
    }
}
