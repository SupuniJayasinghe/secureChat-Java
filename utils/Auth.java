package utils;

import java.util.HashMap;

public class Auth {
    // Maps to store username → hashedPassword and username → salt
    private static final HashMap<String, String> userStore = new HashMap<>();
    private static final HashMap<String, String> saltStore = new HashMap<>();

    // Registers a user by hashing their password and storing it with the salt
    public static void registerUser(String username, String password) throws Exception {
        if (userStore.containsKey(username)) return;
        String salt = Hash.generateSalt();
        String hashedPassword = Hash.hashPassword(password, salt);
        userStore.put(username, hashedPassword);
        saltStore.put(username, salt);
    }

    // Authenticates a user by comparing stored hash with input hash
    public static boolean authenticate(String username, String password) throws Exception {
        if (!userStore.containsKey(username)) return false;
        String salt = saltStore.get(username);
        String hashedInput = Hash.hashPassword(password, salt);
        return userStore.get(username).equals(hashedInput);
    }
}