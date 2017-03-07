package thesis.mhde.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;

public class MHDECipher {

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
	
	public static KeyPair generateRSAKeyPair(int keySize){
		KeyPairGenerator cipherKeyGen=null;
		KeyPair cipherPair=null;
		try {
			cipherKeyGen = KeyPairGenerator.getInstance("RSA");
			cipherKeyGen.initialize(keySize, SecureRandom.getInstance("SHA1PRNG", "SUN"));		
			cipherPair=cipherKeyGen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return cipherPair; 		
	}
	
	
	public static boolean doesDecipherTextMatchPlainText(byte[] plainText, byte[] decipherText){
		
		return Arrays.equals(plainText, decipherText);		
	}
	
	// public static void main(String[] args) {
	// String plainText_1 = MHDERandomNumberGenerator.getNextRandomNumber(64);
	// System.out.println("plain text_1: " + plainText_1);
	//
	// KeyPair kp_1 = generateRSAKeyPair(2048);
	// PublicKey epk_1 = kp_1.getPublic();
	// PrivateKey esk_1 = kp_1.getPrivate();
	//
	// byte[] cipherText_1 = encryptWithRSA(plainText_1.getBytes(), epk_1);
	// byte[] decipherText_1 = decryptWithRSA(cipherText_1, esk_1);
	//
	// String getPlain = new String(decipherText_1);
	// System.out.println("decip text_1: " + getPlain);
	// System.out.println("Does plain text match decipher text: " +
	// plainText_1.equals(new String(decipherText_1)));
	//
	//
	// System.out.println("Does plain text match decipher text: "
	// + doesDecipherTextMatchPlainText(plainText_1.getBytes(),
	// decipherText_1));
	//
	// }

}
