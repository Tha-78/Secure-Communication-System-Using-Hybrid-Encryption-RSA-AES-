# Secure-Communication-System-Using-Hybrid-Encryption-RSA-AES-

## Overview
This project is a hybrid encryption and decryption tool implemented using Python and Streamlit. It combines the strengths of both symmetric encryption (AES) and asymmetric encryption (RSA) to provide a secure way of encrypting and decrypting messages. The application is interactive, user-friendly, and designed for secure message communication.

## TABLE OF CONTENTS

* Features <br>
* Code structure and Function Description<br>
* Visual flow of the app <br>
* How it works<br>
* Conclusion<br>

## FEATURES

* Hybrid Encryption:<br>
    Combines AES for fast data encryption and RSA for secure key exchange.<br>
* Key Management:<br>
    Generates and securely saves RSA key pairs (private and public keys).<br>
* Encryption:<br> 
    Encrypts messages using AES (CBC mode) with RSA-encrypted AES keys.<br>
* Decryption:<br>
    Decrypts AES keys with RSA private keys and recovers the original plaintext.<br>
* Streamlit Interface:<br>
    Provides an interactive web UI for easy encryption and decryption.<br>
* Key Uploading:<br>
    Supports uploading existing RSA keys in PEM format.<br>
* Security:<br>
    Uses AES-256 and RSA-2048 with OAEP padding for strong encryption.<br>
* Base64 Encoding:<br>
    Encodes output for safe sharing over communication channels.<br>
* Error Handling:<br>
    Alerts users about invalid inputs, decryption errors, or corrupted data.<br>
* Scalability:<br>
    Extensible for file encryption or future encryption algorithms.<br>

## CODE STRUCTURE AND FUNCTION DESCRIPTIONS

* Constants and Setup:<br>
       * Defines the directory (KEYS_FOLDER) for storing RSA keys.<br>
       * Ensures the folder exists.<br>
* AES Helper Functions:<br>
      * generate_aes_key(): Creates a 256-bit AES key and 128-bit IV.<br>
      * aes_encrypt(): Encrypts plaintext using AES (CBC mode).<br>
      * aes_decrypt(): Decrypts ciphertext to retrieve plaintext.<br>
* RSA Key Management:<br>
      * generate_rsa_key_pair(): Creates an RSA key pair (2048-bit).<br>
      * save_keys_to_file(): Saves RSA keys to files.<br>
      * load_key_from_file() / load_public_key_from_file(): Loads RSA keys from PEM files.<br>
* Hybrid Encryption and Decryption:<br>
      * hybrid_encrypt(): Encrypts a message using AES for the data and RSA for the AES key. Combines all components into a 
                          Base64-encoded string.<br>
      * hybrid_decrypt(): Decrypts the Base64 string to retrieve the plaintext by reversing the hybrid encryption process.<br>
* Streamlit Integration:<br>
      * Provides a simple web interface for: Generating keys or uploading existing ones.<br>
      * Encrypting plaintext or decrypting Base64-encoded ciphertext. Includes user input fields, file upload options, and result 
       displays.<br>

##  FLOW OF EXECUTION 
* Key Management:<br>
       * Users can generate RSA key pairs or upload existing ones.<br>
* Encryption: <br>
       * Users input plaintext to encrypt.<br>
       * The app generates an AES key, encrypts the message, and secures the AES key with RSA.<br>
       * The final output is a Base64-encoded string.<br>
* Decryption:<br>
       * Users input the Base64-encoded string to decrypt.<br>
       * The app extracts the components, decrypts the AES key using RSA, and retrieves the plaintext using AES.<br>

## HOW IT WORKS

1. Key Generation
    * RSA Key Pair:<br>
            * The program generates a pair of RSA keys (private key and public key) using generate_rsa_key_pair().<br>
            * The private key is stored securely, while the public key can be shared with others for encryption.<br>
    * AES Key:<br>
           * AES requires a symmetric key and an IV (Initialization Vector). These are generated randomly when encrypting a 
             message.<br>
2. Hybrid Encryption Process<br>
             * Step 1: Generate AES Key & IV:<br>
                       A 256-bit AES key and a 128-bit IV are created using os.urandom.<br>
             * Step 2: Encrypt Message with AES:<br>
                      The plaintext message is padded (using PKCS#7) to match the AES block size (128 bits).<br>
                      The padded plaintext is encrypted with the AES key in CBC (Cipher Block Chaining) mode.<br>
             * Step 3: Encrypt AES Key with RSA:<br>
                     The AES key is encrypted using the recipient’s RSA public key (via OAEP padding). This ensures only the 
                     private key owner can decrypt the AES key.<br>
             * Step 4: Combine Data:<br>
                      The IV, RSA-encrypted AES key, and AES-encrypted message are concatenated.<br>
                      The final encrypted data is encoded in Base64 for easier transmission.<br>
3. Hybrid Decryption Process
            * Step 1: Extract Components:<br>
                      The Base64-encoded data is decoded.<br>
                      The IV, RSA-encrypted AES key, and AES-encrypted message are extracted from the decoded data.<br>
            * Step 2: Decrypt AES Key with RSA:<br>
                       The AES key is decrypted using the recipient’s RSA private key.<br>
            * Step 3: Decrypt Message with AES:<br>
                       The AES-encrypted message is decrypted using the AES key and IV.
                       The decrypted message is unpadded to remove padding bytes.


## CONCLUSION
This project demonstrates a secure and efficient hybrid encryption system by combining AES for fast data encryption and RSA for secure key exchange. With a user-friendly Streamlit interface, it ensures robust security and practical usability, making it ideal for real-world applications like secure messaging and data transmission.
