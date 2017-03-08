/**
 * MHDECipher.java - A class to do RSA encryption/ decryption operations and RSA key pair generations. 
 * This class uses already available java cryptography library methods to do RSA cipher operations
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;

public class MHDECipher {

	/**
	 * Performs the RSA encryption operation
	 * 
	 * @param plainText
	 *            the plain text to be encrypted
	 * @param epk
	 *            RSA public key used to encrypt data
	 * @return the cipher text
	 */

	public static byte[] encryptWithRSA(byte[] plainText, PublicKey epk) {
		byte[] cipherText = null;

		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, epk);
			cipherText = cipher.doFinal(plainText);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return cipherText;
	}

	/**
	 * Performs the RSA decryption operation
	 * 
	 * @param cipherText
	 *            the cipher text to be decrypted
	 * @param esk
	 *            RSA private key used to decrypt data
	 * @return the plain text
	 */

	public static byte[] decryptWithRSA(byte[] cipherText, PrivateKey esk) {
		byte[] plainText = null;

		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, esk);
			plainText = cipher.doFinal(cipherText);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return plainText;
	}

	/**
	 * Generate a Public/Private key pair of given bit size
	 * 
	 * @param keySize
	 *            size of the required RSA key in bits
	 * @return a RSA key pair
	 */

	public static KeyPair generateRSAKeyPair(int keySize) {
		KeyPairGenerator cipherKeyGen = null;
		KeyPair cipherPair = null;
		try {
			cipherKeyGen = KeyPairGenerator.getInstance("RSA");
			cipherKeyGen.initialize(keySize, SecureRandom.getInstance("SHA1PRNG", "SUN"));
			cipherPair = cipherKeyGen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return cipherPair;
	}

	/**
	 * Compare a given plain text against it decrypted value of cipher text
	 * 
	 * @param plainText
	 *            the plain text
	 * @param decipherText
	 *            the decrypted cipher text
	 * @return true if two text match, return false otherwise
	 */
	public static boolean doesDecipherTextMatchPlainText(byte[] plainText, byte[] decipherText) {

		return Arrays.equals(plainText, decipherText);
	}

}
