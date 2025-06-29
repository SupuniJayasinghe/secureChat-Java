import utils.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Server {
    public static void main(String[] args) throws Exception {
        // Register a test user for authentication
        Auth.registerUser("userA", "pass123");
        ServerSocket serverSocket = new ServerSocket(5000);
        System.out.println("[SERVER] Listening on port 5000...");

        // Accept connections and handle each client in a new thread
        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new ClientHandler(clientSocket)).start();
        }
    }
}

// Handles communication with a connected client
class ClientHandler implements Runnable {
    private Socket socket;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Receive and verify username/password
            String username = in.readLine();
            String password = in.readLine();

            if (!Auth.authenticate(username, password)) {
                out.println("AUTH_FAIL");
                socket.close();
                return;
            }
            out.println("AUTH_SUCCESS");

            // Generate RSA key pair and send public key
            KeyPair rsaKeys = Crypto.generateRSAKeyPair();
            PrivateKey privateKey = rsaKeys.getPrivate();
            PublicKey publicKey = rsaKeys.getPublic();
            out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            // Receive encrypted AES key, IV and encrypted message
            String encryptedAESKey = in.readLine();
            String ivStr = in.readLine();
            String encryptedMessage = in.readLine();

            // Decrypt AES key and message
            byte[] aesKeyBytes = Crypto.decryptRSA(encryptedAESKey, privateKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivStr));
            String decrypted = Crypto.decryptAES(encryptedMessage, aesKey, iv);

            // Display results
            System.out.println("--- New Message ---");
            System.out.println("Encrypted Message: " + encryptedMessage);
            System.out.println("Decrypted Message: " + decrypted);
            System.out.println("Timestamp: " + java.time.LocalDateTime.now());

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}