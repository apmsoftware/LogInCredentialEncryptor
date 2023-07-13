package encryptor;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class CredentialEncryptor {
	 public static void main(String[] args) throws Exception {
	        // Generate public and private keys
	        KeyPair keyPair = generateKeyPair();
	        PublicKey publicKey = keyPair.getPublic();
	        PrivateKey privateKey = keyPair.getPrivate();

	        // Encrypt a Username using the public key
	        String originalUsernameText = "tomsmith";
	        String encryptedUsernameText = encrypt(originalUsernameText, publicKey);
	        
	        // Encrypt a Password using the public key
	        String originalPasswordText = "SuperSecretPassword!";
	        String encryptedPasswordText = encrypt(originalPasswordText, publicKey);

	        // Print the private key in a string format
	        String privateKeyString = privateKeyToString(privateKey);
	        System.out.println("Private key: " + privateKeyString);
	        
	        // Print the public key in a string format
	        String publicKeyString = publicKeyToString(publicKey);
	        System.out.println("Public key: " + publicKeyString);

	        System.out.println("Encrypted UserName: " + encryptedUsernameText);
	        System.out.println("Decrypted Password: " + encryptedPasswordText);
	    }

	    public static KeyPair generateKeyPair() throws Exception {
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	        keyPairGenerator.initialize(2048);
	        return keyPairGenerator.generateKeyPair();
	    }

	    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
	        return Base64.getEncoder().encodeToString(encryptedBytes);
	    }

	    public static String privateKeyToString(PrivateKey privateKey) {
	        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
	    }
	    
	    public static String publicKeyToString(PublicKey publicKey) {
	        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
	    }


}
