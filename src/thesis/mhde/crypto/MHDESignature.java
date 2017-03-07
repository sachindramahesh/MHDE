package thesis.mhde.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class MHDESignature {

	public static byte[] signWithDSA(byte[] data, PrivateKey ssk) {
		byte[] signedData = null;

		try {
			Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
			dsa.initSign(ssk);
			dsa.update(data);
			signedData = dsa.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return signedData;
	}

	public static boolean verifyWithDSA(byte[] data, byte[] signature, PublicKey pub) {

		boolean doesVerify = false;

		try {
			Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
			dsa.initVerify(pub);
			dsa.update(data);
			doesVerify = dsa.verify(signature);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return doesVerify;
	}

	public static KeyPair generateDSAKeyPair(int keySize) {
		KeyPairGenerator signatureKeyGen = null;
		KeyPair signaturePair = null;

		try {
			signatureKeyGen = KeyPairGenerator.getInstance("DSA", "SUN");
			signatureKeyGen.initialize(keySize, SecureRandom.getInstance("SHA1PRNG", "SUN"));
			signaturePair = signatureKeyGen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return signaturePair;
	}

}
