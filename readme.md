# File Encryption & Decryption

## Information
    simple file encrptor that takes in user inputs to perform encryption and decryption 
    using various algorithms and methods in a secure manner.

#### FileEncryptor.java
    Takes in a single plaintext to perform encryption using a randomly generated 16byte key and initial vector.
    Then returns the generated ciphertext, which can be decrypted back to the original ciphertext with the previously generated key and IV.
    Each round of enc/dec outputs a different ciphertext given the same plaintext.
    
    Algorithm: AES
    
    Cipher mode: CBC with PKCS5PADDING
    
    Argument parameter for:
                        encryption: enc plaintext.txt ciphertext.txt
                        decryption: dec "key" "IV" ciphertext.txt plaintext.txt
    Requirements:
                        plaintext must be placed in the same directory as FileEncryptor.java

#### FileEncryptor2.java
    This time, further extended from FileEncryptor.java, symmetric sectret key is used.
    The specified secret key and the generated IV is then attached to the plaintext
    as metadata so that the user does not have to specify the key and IV each time.
    
    Algorithm: AES
    
    Cipher mode: CBC with PKCS5PADDING
    
    Argument parameter for:
                        encryption: enc "secret key" plaintext.txt ciphertext.txt
                        decryption: dec "secret key" ciphertext.txt plaintext.txt
    Requirements:
                        plaintext must be placed in the same directory as FileEncryptor.java
                        secret key for encryption and decryption must be identical

#### FileEncryptor3.java
    User only needs to specify a password which is used to access the key store which the key pairs are stored in.
    Uses Asymmetric key exchange using the key factory.
    
    Algorithm: AES
        
    Cipher mode: CBC with PKCS5PADDING
        
    Argument parameter for:
                        encryption: enc "password" plaintext.txt ciphertext.txt
                        decryption: dec "password" ciphertext.txt plaintext.txt
    Requirements:
                        plaintext must be placed in the same directory as FileEncryptor.java
                        password for encryption and decryption must be identical

#### FileEncryptor4.java
    In the final stage of modification and extention on FileEncrptor, the program allows the user to
    specify the algorithm (AES or Blowfish), key size, password, as well as encryption or decryption and 
    can print out the meta data information of a given file.
    The secret key pairs are stored in the keystore.
    
    Algorithm: AES or Blowfish
            
    Cipher mode: CBC with PKCS5PADDING
            
    Argument parameter for:
                            AES encryption: enc AES keysize "password" plaintext.txt ciphertext.txt
                            Blowfish encryption: enc Blowfish keysize "password" plaintext.txt ciphertext.txt
                            decryption: dec "password" ciphertext.txt plaintext.txt
                            info: info file.txt
        Requirements:
                            plaintext must be placed in the same directory as FileEncryptor.java
                            password for encryption and decryption must be identical