
# 🔐 Secure Chat Application in Java

A terminal-based secure chat application built using **Java Sockets**, with **AES encryption** for message confidentiality and **RSA encryption** for secure key exchange. Also includes a simple **user authentication system** with password hashing and salting.

---

## 📁 Project Structure

```
.
├── Client.java
├── Server.java
├── utils/
│   ├── Auth.java       # Handles registration and login
│   ├── Crypto.java     # Handles AES & RSA encryption/decryption
│   ├── Hash.java       # Handles password hashing and salting
├── users.txt           # Stores user credentials
└── README.md           # This file
```

---

## ⚙️ Features

- **AES (CBC Mode)** for secure chat messages
- **RSA** public/private key pair for AES key exchange
- **User authentication** system with salted password hashing (SHA-256)
- **Timestamped messages** with clear formatting
- **Multi-threaded server** to handle each client connection concurrently

---

## 📦 Prerequisites

- **Java JDK 8 or higher**
- No external libraries or Maven dependencies are required

---

## 🛠️ Compilation

Compile all Java files:

```bash
javac utils/*.java Server.java Client.java
```

---

## 🚀 How to Run

### Step 1: Start the Server

```bash
java Server
```

This will start the server on `localhost:5000` and wait for client connections.

### Step 2: Run the Client

In a **new terminal window**, run:

```bash
java Client
```

You'll be prompted to:

- **Register** a new user, or
- **Login** with existing credentials

---

## 👥 User Registration & Authentication

### 📌 Register

When prompted:

```
Do you want to [1] Register or [2] Login? Enter 1 or 2:
```

Enter `1` to register a new user. The credentials will be:

- Salted
- Hashed using SHA-256
- Stored in `users.txt` like:
  ```
  username,salt,hashed_password
  ```

### 🔐 Login

Enter `2` to log in with a previously registered user.

If authentication is successful, a secure session begins.

---

## 🔐 Secure Communication Protocol

1. **RSA Key Exchange**
   - Server generates an RSA key pair
   - Sends the **public key** to client

2. **AES Key Transfer**
   - Client generates an AES key
   - Encrypts it using server's **RSA public key**
   - Sends the encrypted AES key to the server

3. **Chat Session Begins**
   - All messages are:
     - Encrypted with AES/CBC/PKCS5Padding
     - Accompanied by a randomly generated **IV**
   - The IV and encrypted message are sent line by line

---

## ❌ Ending the Chat

Type `bye` to gracefully close the connection on either side.

---

## 🔒 Security Overview

| Component           | Method                     |
|--------------------|----------------------------|
| Password Storage    | SHA-256 with random salt   |
| Key Exchange        | RSA (2048-bit)             |
| Message Encryption  | AES (128-bit, CBC mode)    |
| IV Usage            | Random per message         |

---

## 🧠 How It Works (In Short)

1. **Client connects to server**
2. **User registers/logs in**
3. **RSA key is used to securely transfer AES key**
4. **Client and Server use AES for all message encryption/decryption**
5. **Each message includes:**
   - Random IV
   - Encrypted message
   - Timestamped output for clarity

---

## 📌 Notes

- **Multi-client support** is available via threading in the `Server.java`
- The file `users.txt` is created on first run
- This is a **terminal chat app** — no GUI



