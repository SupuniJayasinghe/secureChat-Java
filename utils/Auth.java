package utils;

import java.io.*;
import java.util.HashMap;

public class Auth {
    private static final String FILE_PATH = "users.txt";
    private static final HashMap<String, String> userStore = new HashMap<>();
    private static final HashMap<String, String> saltStore = new HashMap<>();

    static {
        try {
            loadUsers();
        } catch (Exception e) {
            System.out.println("User file not found, starting fresh.");
        }
    }

    // Load users from file into memory
    private static void loadUsers() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(FILE_PATH));
        String line;
        while ((line = br.readLine()) != null) {
            String[] parts = line.split(",");
            if (parts.length == 3) {
                saltStore.put(parts[0], parts[1]);
                userStore.put(parts[0], parts[2]);
            }
        }
        br.close();
    }

    // Write a new user to file
    private static void saveUser(String username, String salt, String hashedPassword) throws Exception {
        FileWriter fw = new FileWriter(FILE_PATH, true);
        fw.write(username + "," + salt + "," + hashedPassword + "\n");
        fw.close();
    }

    // Register and save new user
    public static boolean registerUser(String username, String password) throws Exception {
        if (userStore.containsKey(username)) {
            return false; // user exists
        }
        String salt = Hash.generateSalt();
        String hashed = Hash.hashPassword(password, salt);
        userStore.put(username, hashed);
        saltStore.put(username, salt);
        saveUser(username, salt, hashed);
        return true;
    }

    // Authenticate existing user
    public static boolean authenticate(String username, String password) throws Exception {
        if (!userStore.containsKey(username))
            return false;
        String salt = saltStore.get(username);
        String hashedInput = Hash.hashPassword(password, salt);
        return userStore.get(username).equals(hashedInput);
    }
}
