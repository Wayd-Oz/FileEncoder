//package com.packtpub.crypto.section5;

//import com.packtpub.crypto.Util;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erik Costlow
 * modified & extended by Wade S. Oh
 *
 */
public class FileEncryptor {

    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {

        //get user input for encryption and decryption specifications
        if(args[0].equals("enc")) {

            // plaintext, ciphertext
            encrypt(args[1], args[2]);

        } else if(args[0].equals("dec")) {

            // key, iv, chiphertext, plaintext
            decrypt(args[1].toCharArray(), args[2].toCharArray(), args[3], args[4]);

        } else {
            System.out.println("Invalid function name: " + args[0]);
        }
    }

    private static void encrypt(String plaintext, String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        // this snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] key = new byte[16];
        sr.nextBytes(key); // 128 bit key
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        System.out.println("Random key=" + Util.bytesToHex(key));
        System.out.println("initVector=" + Util.bytesToHex(initVector));
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        // look for files here
         final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + ciphertext);
        // final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + ciphertext);

        try (InputStream fin = FileEncryptor.class.getResourceAsStream(plaintext);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            final byte[] bytes = new byte[1024];
            for(int length = fin.read(bytes); length !=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    private static void decrypt(char[] skey, char[] siv, String ciphertext, String plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        byte[] k = getBytes(String.valueOf(skey));
        byte[] initVector = getBytes(String.valueOf(siv));
        SecretKeySpec keySpec = new SecretKeySpec(k, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);


        final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + ciphertext);
        final Path decryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + plaintext);
        // final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + ciphertext);
        // final Path decryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + plaintext);

        try(InputStream encryptedData = Files.newInputStream(encryptedPath);
            CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }

    /**
     * Get array of bytes from string of hex values
     *
     * @param hex
     * @return array of bytes
     */
    private static byte[] getBytes(String hex) {
        String[] splitIV = hex.split(" ");
        byte[] hexDec = new byte[16];

        for (int i = 0; i < hexDec.length; i++) {
            hexDec[i] = getDecimal(splitIV[i]);
        }

        return hexDec;
    }

    /**
     * https://www.javatpoint.com/java-hex-to-decimal
     *
     * @param hex
     * @return decimal of hex
     */
    private static byte getDecimal(String hex) {
        String digits = "0123456789ABCDEF";
        hex = hex.toUpperCase();
        byte val = 0;
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            int d = digits.indexOf(c);
            val = (byte) (16 * val + d);
        }
        return val;
    }
}
