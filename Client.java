import utils.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Client {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 5000);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        Scanner scanner = new Scanner(System.in);

        System.out.print("Do you want to [1] Register or [2] Login? Enter 1 or 2: ");
        String option = scanner.nextLine().trim();

        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        if (option.equals("1")) {
            out.println("REGISTER");
            out.println(username);
            out.println(password);

            String response = in.readLine();
            if ("REGISTER_SUCCESS".equals(response)) {
                System.out.println("Registration successful. You can now login.");
            } else {
                System.out.println("Username already exists. Try logging in.");
            }
            socket.close();
            return;
        } else if (!option.equals("2")) {
            System.out.println("Invalid option selected.");
            socket.close();
            return;
        }

        // LOGIN
        out.println("LOGIN");
        out.println(username);
        out.println(password);

        if (!"AUTH_SUCCESS".equals(in.readLine())) {
            System.out.println("Authentication failed.");
            socket.close();
            return;
        }
        System.out.println("Authenticated!");

        String pubKeyStr = in.readLine();
        byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

        SecretKey aesKey = Crypto.generateAESKey();
        String encryptedAESKey = Crypto.encryptRSA(aesKey.getEncoded(), serverPublicKey);
        out.println(encryptedAESKey);

        System.out.println("[CLIENT] Secure chat started.");

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

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

                    System.out.println("[" + dtf.format(LocalDateTime.now()) + "] [Server Decrypted]: " + decryptedMsg);
                    System.out.println("-------------------------------\n");

                    if ("bye".equalsIgnoreCase(decryptedMsg.trim())) {
                        System.out.println("[CLIENT] Server ended the chat.");
                        socket.close();
                        break;
                    }
                }

            } catch (Exception e) {
                if (!socket.isClosed())
                    System.out.println("[CLIENT] Read thread error: " + e.getMessage());
            }
        });

        Thread writeThread = new Thread(() -> {
            try {
                while (!socket.isClosed()) {
                    System.out.print("[Client] Enter message: ");
                    String msgToSend = scanner.nextLine();

                    IvParameterSpec iv = Crypto.generateIV();
                    String ivStr = Base64.getEncoder().encodeToString(iv.getIV());
                    String encryptedMsg = Crypto.encryptAES(msgToSend, aesKey, iv);

                    out.println(ivStr);
                    out.println(encryptedMsg);

                    System.out.println("[" + dtf.format(LocalDateTime.now()) + "] [Client sent encrypted message]");

                    if ("bye".equalsIgnoreCase(msgToSend.trim())) {
                        System.out.println("[CLIENT] You ended the chat.");
                        socket.close();
                        break;
                    }
                }
            } catch (Exception e) {
                if (!socket.isClosed())
                    System.out.println("[CLIENT] Write thread error: " + e.getMessage());
            }
        });

        readThread.start();
        writeThread.start();

        readThread.join();
        writeThread.join();

        System.out.println("[CLIENT] Connection closed.");
        socket.close();
    }
}
