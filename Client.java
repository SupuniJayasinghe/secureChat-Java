import utils.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.util.Base64;
import java.security.spec.X509EncodedKeySpec;


public class Client {
    public static void main(String[] args) throws Exception {
        // Connect to server
        Socket socket = new Socket("localhost", 5000);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Provide username and password for login
        String username = "userA";
        String password = "pass123";

        out.println(username);
        out.println(password);

        // Check authentication result
        if (!in.readLine().equals("AUTH_SUCCESS")) {
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
