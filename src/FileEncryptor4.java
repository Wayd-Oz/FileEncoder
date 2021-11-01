//package com.packtpub.crypto.section5;

//import com.packtpub.crypto.Util;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;
import java.util.HashMap;
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

public class FileEncryptor4 {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

    //two different algorithms for enc & dec
    private static HashMap<String, String> algorithm = new HashMap<String, String>();

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        //AES and Blowfish algorithm
        algorithm.put("AES", "AES/CBC/PKCS5PADDING");
        algorithm.put("Blowfish", "Blowfish/CBC/PKCS5PADDING");

        //get user input for encryption and decryption specifications
        if(args[0].equals("enc")) {

            //user inputs for encryption
            String alg = args[1];
            String keySize = args[2];
            char[] password = args[3].toCharArray();
            String plaintext = args[4];
            String ciphertext = args[5];

            //double check if the user has chosen either AES or Blowfish
            if(alg.equals("AES") || alg.equals("Blowfish")) {
                encrypt(alg, keySize, password, plaintext, ciphertext);
            }else {
                System.out.println("Invalid algorithm: " + alg);
                System.out.println("Type in either AES or Blowfish.");
            }

        } else if(args[0].equals("dec")) {

            //user inputs for decryption
            char[] password = args[1].toCharArray();
            String ciphertext = args[2];
            String plaintext = args[3];

            decrypt(password, ciphertext, plaintext);

        } else if(args[0].equals("info")) {

            //retrieve metadata from args1 ciphertext.enc
            String[] info = info(args[1]);
            System.out.println("Metadata from " + args[1] + ": " + info[0] + ", " + info[1]);

        }else {
            System.out.println("Invalid function name: " + args[0]);
        }
    }

    private static void encrypt(String alg, String keySize, char[] password, String plaintext, String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, IOException {

        //This snippet is literally copied from SymmetrixExample
        SecureRandom sr = new SecureRandom();
        byte[] initVector;

        //Different key size for the algorithm
        if(alg.equals("AES")) {
            initVector = new byte[16];
        } else {
            initVector = new byte[8];
        }

        sr.nextBytes(initVector); // 16 bytes IV
        byte[] key = getKey(password, initVector, Integer.parseInt(keySize));
        System.out.println("Secret key=" + Util.bytesToHex(key));
        System.out.println("initVector=" + Util.bytesToHex(initVector));
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, alg);
        Cipher cipher = Cipher.getInstance(algorithm.get(alg));
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        //Look for files here
        final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + ciphertext);
        //final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + ciphertext);

        try (InputStream fin = FileEncryptor4.class.getResourceAsStream(plaintext);
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

        //Add key length and algorithm type as metadata
        //https://docs.oracle.com/javase/7/docs/api/java/nio/file/Files.html#getFileAttributeView(java.nio.file.Path,%20java.lang.Class,%20java.nio.file.LinkOption...)
        UserDefinedFileAttributeView algAtt = Files.getFileAttributeView(encryptedPath, UserDefinedFileAttributeView.class);
        algAtt.write("algorithm", Charset.defaultCharset().encode(alg));
        UserDefinedFileAttributeView keyAtt = Files.getFileAttributeView(encryptedPath, UserDefinedFileAttributeView.class);
        keyAtt.write("keySize", Charset.defaultCharset().encode(keySize));
    }

    private static void decrypt(char[] password, String ciphertext, String plaintext) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + ciphertext);
        final Path decryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + plaintext);
        //final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + ciphertext);
        //final Path decryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + plaintext);

        //Retrieve the algorithm and key size
        String alg = readMetaData(encryptedPath, "algorithm");
        String keySize = readMetaData(encryptedPath, "keySize");
        System.out.println("Algorithm info found in Metadata: " + alg);
        System.out.println("key length found in Metadata: " + keySize);

        //Retrieve the IV from first 16 bytes of ciphertext
        InputStream encryptedData = Files.newInputStream(encryptedPath);
        byte[] initVector;

        //Different key size for algorithm
        if(alg.equals("AES")) {
            initVector = new byte[16];
            encryptedData.readNBytes(initVector, 0, 16);
        } else {
            initVector = new byte[8];
            encryptedData.readNBytes(initVector, 0, 8);
        }

        //Retrieve the secret key from argument parameter
        byte[] k = getKey(password, initVector, Integer.parseInt(keySize));
        SecretKeySpec keySpec = new SecretKeySpec(k, alg);

        IvParameterSpec ivSpec = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(algorithm.get(alg));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        //Decrypt the rest of the original cipher text
        try(CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath)){
            final byte[] bytes = new byte[1024];
            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor4.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }

    //Read in metadata from the given ciphertext.enc
    private static String[] info(String ciphertext) {

        final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + "/src/" + ciphertext);
        //final Path encryptedPath = FileSystems.getDefault().getPath(System.getProperty("user.dir") + ciphertext);

        String[] info = new String[2];
        info[0] = (readMetaData(encryptedPath, "algorithm"));
        info[1] = (readMetaData(encryptedPath, "keySize"));

        return info;
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

    private static byte[] getKey(char[] password, byte[] initVector, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException {

        KeySpec spec = new PBEKeySpec(password, initVector, 1000, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();

        return key;
    }

    /**
     * https://www.tabnine.com/code/java/methods/java.nio.file.Files/getFileAttributeView
     *
     * Gets value of given attribute of file
     *
     * @param encryptedPath file to read attribute from
     * @param attName name of attribute to read
     * @return String value
     */
    private static String readMetaData(Path encryptedPath, String attName) {
        String value = "";
        Path path = encryptedPath;
        UserDefinedFileAttributeView view = Files.getFileAttributeView(path,UserDefinedFileAttributeView.class);
        String name = attName;
        ByteBuffer buf = null;
        try {
            buf = ByteBuffer.allocate(view.size(name));
            view.read(name, buf);
            buf.flip();
            value = Charset.defaultCharset().decode(buf).toString();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return value;
    }
}
