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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Erik Costlow
 * modified & extended by Wade S. Oh
 *
 */
public class FileEncryptor3 {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        //get user input for encryption and decryption specifications
        if(args[0].equals("enc")) {

            //password, plaintxt, ciphertxt
            encrypt(args[1].toCharArray(), args[2], args[3]);

        } else if(args[0].equals("dec")) {

            //password, ciphertxt, plaintxt
            decrypt(args[1].toCharArray(), args[2], args[3]);

        } else {
            System.out.println("Invalid function name: " + args[0]);
        }
    }

    private static void encrypt(char[] password, String plaintext, String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {

        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] initVector = new byte[16];
        sr.nextBytes(initVector); // 16 bytes IV
        byte[] key = getKey(password, initVector);
        System.out.println("Secret key=" + Util.bytesToHex(key));
        System.out.println("initVector=" + Util.bytesToHex(initVector));
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        //Look for files here
        final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + ciphertext);
        //final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + ciphertext);

        try (InputStream fin = FileEncryptor3.class.getResourceAsStream(plaintext);
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {

            //Attach the IV to the beginning of file- cipher text
            fout.write(initVector);

            final byte[] bytes = new byte[1024];
            for(int length = fin.read(bytes); length !=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        LOG.info("Encryption finished, saved at " + encryptedPath);
    }

    private static void decrypt(char[] password, String ciphertext, String plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + ciphertext);
        final Path decryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + plaintext);
        //final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + ciphertext);
        //final Path decryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + plaintext);

        //Retrieve the IV from first 16 bytes of ciphertext
        InputStream encryptedData = Files.newInputStream(encryptedPath);
        byte[] initVector = new byte[16];
        encryptedData.readNBytes(initVector, 0, 16);

        //Retrieve the secret key from argument parameter
        byte[] k = getKey(password, initVector);
        SecretKeySpec keySpec = new SecretKeySpec(k, ALGORITHM);

        IvParameterSpec ivSpec = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        //Decrypt the rest of the original cipher text
        try(CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor3.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }

    /**
     * Get array of bytes from string of hex values
     *
     * @param hex
     * @return array of bytes
     */
    public static byte[] getBytes(String hex) {
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

    private static byte[] getKey(char[] password, byte[] initVector) throws NoSuchAlgorithmException, InvalidKeySpecException {

        //generate secret key using the given password
        KeySpec spec = new PBEKeySpec(password, initVector, 1000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();

        return key;
    }
}
