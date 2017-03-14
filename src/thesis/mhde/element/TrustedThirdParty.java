/**
 * TrustedThirdParty.java - A class that implements the behaviour of the Trusted-Third-Party as required by the MHDE protocol. 
 * This class uses the singleton design pattern.
 */

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
	private static String secretK;// the secret key K shared by the prover and
									// verifier

	private TrustedThirdParty() {
	}

	private static TrustedThirdParty ttp = new TrustedThirdParty();

	public static TrustedThirdParty getInstance() {
		return ttp;
	}

	/**
	 * Generates all the keys required by each user to participate in the MHDE
	 * protocol. The keys include: the secret n-bit key K shared by the prover
	 * and the verifier, the verifiers cipher keys, the signing keys for all the
	 * users
	 * 
	 * @param numOfPaths
	 *            total number of paths that participate in the MHDE protocol
	 * @param pathList
	 *            listing of all the paths
	 * @param n
	 *            size of n
	 */
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

	/**
	 * Returns the signing key pair of the specified user
	 * 
	 * @param uname
	 *            name of the node
	 * @return the signing key pair
	 */
	public static KeyPair getSignKP(String uname) {
		return keysSet.get(uname);
	}

	/**
	 * Returns the cipher key pair of the specified user
	 * 
	 * @param uname
	 *            name of the node
	 * @return the cipher key pair
	 */
	public static KeyPair getCipherKP(String uname) {
		return keysSet.get(uname);
	}

	/**
	 * Generate the secret key K shared between the prover and the verifier
	 * 
	 * @param keySize
	 *            size of the key
	 */
	private static void setSecretK(int keySize) {
		secretK = MHDERandomNumberGenerator.getNextRandomNumber(keySize);
	}

	/**
	 * Returns the secret key K shared between the prover and the verifier
	 * 
	 * @return the secret key K
	 */
	public static String getSecretK() {
		return secretK;
	}

	/**
	 * Returns the verifiers' public sign key used to verify the verifier's
	 * signature
	 * 
	 * @return verifier's public sign key
	 */
	public static PublicKey getVerifierPublicKey_Sign() {
		return keysSet.get("V").getPublic();
	}

	/**
	 * Returns the verifier's public encryption key used to encrypt data
	 * intended for the verifier
	 * 
	 * @return verifier's public encryption key
	 */
	public static PublicKey getVerifierPublicKey_Encrypt() {
		return keysSet.get("VC").getPublic();
	}

	/**
	 * Returns the specified user's public sign key
	 * 
	 * @param username
	 *            name of the user node
	 * @return public sign key
	 */
	public PublicKey getUserPublicKey_Sign(String username) {
		return keysSet.get(username).getPublic();
	}

}
