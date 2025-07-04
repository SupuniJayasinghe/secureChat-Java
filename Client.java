import utils.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    public static void main(String[] args) throws Exception {
        // Connect to server
        Socket socket = new Socket("localhost", 5000);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        Scanner scanner = new Scanner(System.in);

        System.out.print("Do you want to [1] Register or [2] Login? Enter 1 or 2: ");
        String option = scanner.nextLine().trim();

        String username, password;

        System.out.print("Enter username: ");
        username = scanner.nextLine();
        System.out.print("Enter password: ");
        password = scanner.nextLine();

        if (option.equals("1")) {
            if (utils.Auth.registerUser(username, password)) {
                System.out.println("Registration successful. You can now login.");
            } else {
                System.out.println("sername already exists. Try logging in.");
                return;
            }
        }

        // Send credentials to server for authentication
        out.println(username);
        out.println(password);

        // Check authentication result
        if (!in.readLine().equals("AUTH_SUsCCESS")) {
            System.out.println("Authentication failed.");
            return;
        }

        System.out.println("Authenticated!");

        // Receive RSA public key from server
        String pubKeyStr = in.readLine();
        byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

        // Generate AES key and IV
        SecretKey aesKey = Crypto.generateAESKey();
        IvParameterSpec iv = Crypto.generateIV();

        // Encrypt AES key with server's public RSA key
        String encryptedAESKey = Crypto.encryptRSA(aesKey.getEncoded(), serverPublicKey);
        String ivString = Base64.getEncoder().encodeToString(iv.getIV());

        // Read message from user input and encrypt it
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter message: ");
        String message = sc.nextLine();
        String encryptedMessage = Crypto.encryptAES(message, aesKey, iv);

        // Send encrypted AES key, IV, and encrypted message to server
        out.println(encryptedAESKey);
        out.println(ivString);
        out.println(encryptedMessage);

        System.out.println("Encrypted Message Sent!");
        System.out.println("Timestamp: " + java.time.LocalDateTime.now());

        socket.close();
    }
}
