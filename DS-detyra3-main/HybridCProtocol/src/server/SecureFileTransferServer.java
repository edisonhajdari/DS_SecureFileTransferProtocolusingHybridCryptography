package server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;

public class SecureFileTransferServer {
    private static final int PORT = 12345;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private static final String SERVER_FILES_DIR = "server_files";
    private KeyPair rsaKeyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public SecureFileTransferServer() throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();
        privateKey = rsaKeyPair.getPrivate();
        publicKey = rsaKeyPair.getPublic();

        // Ensure the server files directory exists
        Files.createDirectories(Paths.get(SERVER_FILES_DIR));
    }

    public void start() throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Secure File Transfer Server is running...");
        while (true) {
            try (Socket clientSocket = serverSocket.accept()) {
                System.out.println("Client connected, exchanging keys...");
                handleClient(clientSocket);
            }
        }
    }

    private void handleClient(Socket clientSocket) throws Exception {
        DataInputStream input = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream output = new DataOutputStream(clientSocket.getOutputStream());

        // Send server's public key to the client
        output.writeInt(publicKey.getEncoded().length);
        output.write(publicKey.getEncoded());

        // Receive client's public key
        int length = input.readInt();
        byte[] clientPublicKeyBytes = new byte[length];
        input.readFully(clientPublicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PublicKey clientPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(clientPublicKeyBytes));

        // Receive encrypted AES key
        length = input.readInt();
        byte[] encryptedAesKey = new byte[length];
        input.readFully(encryptedAesKey);

        // Decrypt AES key
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, AES_ALGORITHM);

        // Handle file upload
        String fileName = input.readUTF();
        System.out.println("Receiving file: " + fileName);

        // Receive file signature
        length = input.readInt();
        byte[] fileSignature = new byte[length];
        input.readFully(fileSignature);

        // Receive file data
        length = input.readInt();
        byte[] encryptedFileData = new byte[length];
        input.readFully(encryptedFileData);

        // Decrypt file data
        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] fileData = aesCipher.doFinal(encryptedFileData);

        // Print the decrypted file content (for debugging purposes)
        System.out.println("Decrypted File Data: " + new String(fileData, StandardCharsets.UTF_8));

        // Verify file integrity and authenticity
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fileHash = digest.digest(fileData);
        Signature sig = Signature.getInstance(SIGN_ALGORITHM);
        sig.initVerify(clientPublicKey);
        sig.update(fileHash);
        if (!sig.verify(fileSignature)) {
            System.out.println("File signature verification failed.");
            return;
        }

        // Save the file
        File outputFile = new File("server_files/" + fileName);
        Files.write(outputFile.toPath(), fileData);
        System.out.println("File received and stored: " + fileName);
    }


    public static void main(String[] args) throws Exception {
        new SecureFileTransferServer().start();
    }
}
