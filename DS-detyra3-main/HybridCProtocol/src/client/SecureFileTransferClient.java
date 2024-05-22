package client;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SecureFileTransferClient extends JFrame {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String SIGN_ALGORITHM = "SHA256withRSA";
    private KeyPair rsaKeyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey serverPublicKey;
    private JTextField filePathField;

    public SecureFileTransferClient() throws Exception {
        super("Secure File Transfer Client");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 150);
        setLocationRelativeTo(null);

        // Layout setup
        JPanel panel = new JPanel(new BorderLayout());
        JLabel label = new JLabel("Select file for transfer:");
        filePathField = new JTextField();
        JButton browseButton = new JButton("Browse");
        JButton transferButton = new JButton("Transfer");

        panel.add(label, BorderLayout.NORTH);
        panel.add(filePathField, BorderLayout.CENTER);
        panel.add(browseButton, BorderLayout.EAST);
        panel.add(transferButton, BorderLayout.SOUTH);

        add(panel);

        // Action Listeners
        browseButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    filePathField.setText(selectedFile.getAbsolutePath());
                }
            }
        });

        transferButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    connectAndTransferFile(filePathField.getText());
                } catch (Exception ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Error occurred: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        setVisible(true);

        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048);
        rsaKeyPair = keyGen.generateKeyPair();
        privateKey = rsaKeyPair.getPrivate();
        publicKey = rsaKeyPair.getPublic();
    }

    public void connectAndTransferFile(String filePath) throws Exception {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT)) {
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // Receive server's public key
            int length = input.readInt();
            byte[] serverPublicKeyBytes = new byte[length];
            input.readFully(serverPublicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPublicKeyBytes));

            // Send client's public key
            output.writeInt(publicKey.getEncoded().length);
            output.write(publicKey.getEncoded());

            // Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();

            // Encrypt AES key with server's public key
            Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
            output.writeInt(encryptedAesKey.length);
            output.write(encryptedAesKey);

            // Read file data
            File file = new File(filePath);
            byte[] fileData = Files.readAllBytes(file.toPath());

            // Encrypt file data
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedFileData = aesCipher.doFinal(fileData);

            // Print the encrypted file content (for debugging purposes)
            System.out.println("Encrypted File Data: " + Base64.getEncoder().encodeToString(encryptedFileData));

            // Generate file hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fileHash = digest.digest(fileData);

            // Sign the file hash
            Signature sig = Signature.getInstance(SIGN_ALGORITHM);
            sig.initSign(privateKey);
            sig.update(fileHash);
            byte[] fileSignature = sig.sign();

            // Send file name, signature, and data
            output.writeUTF(file.getName());
            output.writeInt(fileSignature.length);
            output.write(fileSignature);
            output.writeInt(encryptedFileData.length);
            output.write(encryptedFileData);
            System.out.println("File '" + file.getName() + "' encrypted and sent successfully.");
        }
    }

    public static void main(String[] args) throws Exception {
        new SecureFileTransferClient();
    }
}
