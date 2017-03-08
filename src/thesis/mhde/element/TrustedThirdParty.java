package thesis.mhde.element;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;

import thesis.mhde.crypto.MHDECipher;
import thesis.mhde.crypto.MHDERandomNumberGenerator;
import thesis.mhde.crypto.MHDESignature;

public class TrustedThirdParty {

	private static HashMap<String, KeyPair> keysSet = new HashMap<String, KeyPair>();// keys
																						// for
																						// signing
	private static String secretK;

	private TrustedThirdParty() {
	}

	private static TrustedThirdParty ttp = new TrustedThirdParty();

	public static TrustedThirdParty getInstance() {
		return ttp;
	}

	public static void registerUsers(int numOfPaths, HashMap<String, String> pathList, int n) {
		setSecretK(n);

		int keySize = 4096;
		if (n == 64)
			keySize = 1024;
		else if (n == 128)
			keySize = 2048;
		else if (n == 256)
			keySize = 4096;

		try {
			KeyPair verifierPair = MHDESignature.generateDSAKeyPair(2048);
			keysSet.put("V", verifierPair);
			KeyPair proverPair = MHDESignature.generateDSAKeyPair(2048);
			keysSet.put("U", proverPair);

			for (int i = 1; i <= numOfPaths; i++) {
				String[] users = pathList.get("path_" + i).split("\\s*,\\s*");
				for (int j = 1; j < users.length - 1; j++) {
					KeyPair pair = MHDESignature.generateDSAKeyPair(2048);
					keysSet.put(users[j].trim(), pair);
				}
			}

			KeyPair cipherPair = MHDECipher.generateRSAKeyPair(keySize);
			keysSet.put("VC", cipherPair);// verifier cipher keys
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static KeyPair getSignKP(String uname) {
		return keysSet.get(uname);
	}

	public static KeyPair getCipherKP(String uname) {
		return keysSet.get(uname);
	}

	private static void setSecretK(int keySize) {
		secretK = MHDERandomNumberGenerator.getNextRandomNumber(keySize);
	}

	public static String getSecretK() {
		return secretK;
	}

	public static PublicKey getVerifierPublicKey_Sign() {
		return keysSet.get("V").getPublic();
	}

	public static PublicKey getVerifierPublicKey_Encrypt() {
		return keysSet.get("VC").getPublic();
	}

	public PublicKey getUserPublicKey_Sign(String username) {
		return keysSet.get(username).getPublic();
	}

}
