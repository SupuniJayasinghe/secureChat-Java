package utils;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class Hash {
    // Hashes a password using SHA-256 and a given salt
    public static String hashPassword(String password, String salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt.getBytes());
        byte[] hashedBytes = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hashedBytes);
    }

    // Generates a random salt encoded in Base64
    public static String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}
