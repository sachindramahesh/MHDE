/**
 * Verifier.java - The Verifier class that extends the BasicNode abstract class. Implement the functionalities specific to the verifier
 *  
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.element;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import thesis.mhde.crypto.MHDECipher;
import thesis.mhde.crypto.MHDECommitment;
import thesis.mhde.crypto.MHDERandomNumberGenerator;
import thesis.mhde.crypto.MHDESignature;
import thesis.mhde.crypto.MHDEXor;

public class Verifier extends BasicNode {

	private String verifyingPath;// a single path the MHDE protocol is run on
	private PrivateKey signSK;// private DSA sign key
	private PrivateKey encryptSK;// private RSA encryption key
	private String[] challenge;// challenges generated
	private String[] response;// responses received
	private String[] users;// users in the single path
	private String secretKey_K;// secret n-bit key K shared between prover and
								// verifier
	private String pathNum;// number of the single path
	private double[] timeLapse;// time taken to run each challenge-response round
	private String proverResponses;// prover responses deduced by the verifier
									// based on its information

	public Verifier(String nodeName, Link leftLink, int n, String path, KeyPair signKP, KeyPair cipherkP, String sk_k,
			String pathNum) {
		super(nodeName, leftLink, null, n);
		this.verifyingPath = path;
		this.users = path.split("\\s*,\\s*");
		this.signSK = signKP.getPrivate();
		this.challenge = new String[n];
		this.response = new String[n];
		this.encryptSK = cipherkP.getPrivate();
		this.secretKey_K = sk_k;
		this.pathNum = pathNum;
		this.timeLapse = new double[n + 1];
		this.timeLapse[n] = users.length - 1;
		this.proverResponses = null;
	}

	@Override
	public void run() {
		Link l_link = this.getLeftLink();
		int rounds = this.getN();
		String name = this.getNodeName();
		synchronized (l_link) {
			this.phaseZero();
			l_link.setFlag(l_link.getLeftNode());
			l_link.notify();
		}

		for (int i = 0; i < rounds; i++) {
			synchronized (l_link) {
				if (!l_link.getFlag().equals(name)) {
					try {
						l_link.wait();
					} catch (InterruptedException e) {
					}
				}
				if (i == 0) {
					this.phaseOne();
				} else if (i > 0) {
					this.response[i - 1] = l_link.getResponse();
					timeLapse[i - 1] = l_link.getTimer();
					System.out.println(name + " @round=" + (i - 1) + " challenge=" + challenge[i - 1] + " response="
							+ response[i - 1] + " lapsed time = " + timeLapse[i - 1] + "ns");

				}
				this.phaseTwo(i);

				l_link.setFlag(l_link.getLeftNode());
				l_link.notify();
			}
		}

		synchronized (l_link) {
			if (!l_link.getFlag().equals(name)) {
				try {
					l_link.wait();
				} catch (InterruptedException e) {
				}
			}
			this.response[rounds - 1] = l_link.getResponse();
			timeLapse[rounds - 1] = l_link.getTimer();
			System.out.println(name + " @round=" + (rounds - 1) + " challenge=" + challenge[rounds - 1] + " response="
					+ response[rounds - 1] + " lapsed time = " + timeLapse[rounds - 1] + "ns");

			System.out.println("\t====PHASE-II COMPLETED====\n\n ");
			System.out.println("\t====PHASE-III STARTED==== ");

			l_link.setFlag(l_link.getLeftNode());
			l_link.notify();
		}

		synchronized (l_link) {
			if (!l_link.getFlag().equals(name)) {
				try {
					l_link.wait();
				} catch (InterruptedException e) {
				}
			}
			VerifierProxy.setTiming(pathNum, timeLapse);
			this.phaseThree();
		}

		synchronized (this) {// notify to proceed to next path
			this.notify();
		}
	}

	/* Executes the phase-0 of the protocol */
	private void phaseZero() {

		byte[] sign = MHDESignature.signWithDSA(this.verifyingPath.getBytes(), this.signSK);
		this.getLeftLink().setPhase0_data(this.verifyingPath.getBytes(), sign);
		System.out.println("\t====PHASE-0 STARTED==== ");

	}

	/*
	 * Executes the phase-1 of the protocol. Verifier actually does nothing at
	 * this phase
	 */
	private void phaseOne() {
		System.out.println("\t====PHASE-I COMPLETED====\n\n");
		System.out.println("\t====PHASE-II STARTED==== ");

	}

	/*
	 * Executes the phase-2 of the MHDE protocol. Generates a random 1-bit
	 * string and send it to the next proxy on the path
	 */
	private void phaseTwo(int round) {
		Link l_link = this.getLeftLink();
		String challenge = MHDERandomNumberGenerator.getARandomBit();
		this.challenge[round] = challenge;
		l_link.setChallenge(challenge);
		l_link.setTimer(l_link.getDelay());
	}

	/* Executes the phase-3 of the MHDE protocol. Does verification process */
	private void phaseThree() {
		int numOfMaliciousProxies = this.validateProxies();
		boolean doResponsesMatchChallenges = this.validateProverResponses();
		boolean isProverHonest = this.validateProver();

		if (numOfMaliciousProxies == 0 && doResponsesMatchChallenges && isProverHonest) {
			VerifierProxy.updateAuthentication(new Boolean(true));
			System.out.println("AUTHENTICATION BIT = 1");
		} else {
			if (numOfMaliciousProxies > 0) {
				System.out.println("There are " + numOfMaliciousProxies + " malicious proxies");
			}
			if (!doResponsesMatchChallenges) {
				System.out.println("There are unmatches challenges and responses");
			}
			if (!isProverHonest) {
				System.out.println("The prover is malicious");
			}

			VerifierProxy.updateAuthentication(new Boolean(false));
			System.out.println("AUTHENTICATION BIT = 0");
		}
	}

	/* Helper method to validate the proxies */
	private int validateProxies() {
		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		VerifierProxy vProxy = VerifierProxy.getInstance();
		HashMap<String, byte[]> commits = vProxy.getCommits();
		HashMap<String, byte[]> signedCommits = vProxy.getSignedCommits();
		HashMap<String, byte[][]> openings = vProxy.getOpenings();
		HashMap<String, byte[][]> signedOpenings = vProxy.getSignedOpenings();

		boolean verify_commit_sign = false;
		boolean verify_r_sign = false;
		boolean verify_offset_sign = false;
		boolean verify_open_commit = false;

		int maliciousProxies = 0;

		for (int i = 1; i < users.length - 1; i++) {
			String user = users[i];
			PublicKey signPK = ttp.getUserPublicKey_Sign(user);

			verify_commit_sign = MHDESignature.verifyWithDSA(commits.get(user), signedCommits.get(user), signPK);
			verify_r_sign = MHDESignature.verifyWithDSA(openings.get(user)[0], signedOpenings.get(user)[0], signPK);
			verify_offset_sign = MHDESignature.verifyWithDSA(openings.get(user)[1], signedOpenings.get(user)[1],
					signPK);
			verify_open_commit = MHDECommitment.verifyWithPederson(openings.get(user)[0], openings.get(user)[1],
					commits.get(user));

			if (verify_commit_sign && verify_r_sign && verify_offset_sign && verify_open_commit) {
				System.out.println(users[i] + " is honest");
			} else {
				String response = "";
				if (!verify_commit_sign) {
					response = response.concat(";unmatched commit and sign");
				}
				if (!(verify_r_sign & verify_offset_sign)) {
					response = response.concat(";unmatched opening and sign");
				}
				if (!verify_open_commit) {
					response = response.concat(";unmatched commit and opening");
				}
				System.out.println(users[i] + " is malicious(" + response + ")");
				maliciousProxies++;
			}
		}

		return maliciousProxies;
	}

	/* Helper method to validate the prover responses. */
	private boolean validateProverResponses() {
		String proverOffset = "";
		String proverResponseBit = null;
		String secretKeyBit = null;
		this.proverResponses = this.computeProverResponses();

		for (int i = 0; i < this.getN(); i++) {
			proverResponseBit = MHDEXor.bitAt(proverResponses, i);
			if (challenge[i].equals("0")) {
				proverOffset = proverOffset.concat(proverResponseBit);
			} else if (challenge[i].equals("1")) {
				secretKeyBit = MHDEXor.bitAt(secretKey_K, i);
				proverOffset = proverOffset.concat(MHDEXor.xorBits(proverResponseBit, secretKeyBit));
			}
		}
		proverOffset = proverOffset.trim();

		// TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		VerifierProxy vProxy = VerifierProxy.getInstance();
		HashMap<String, byte[][]> openings = vProxy.getOpenings();
		String pOffset = new String(MHDECipher.decryptWithRSA(openings.get("U")[1], this.encryptSK));

		boolean isOK = pOffset.equals(proverOffset);
		System.out.println("do challenges and reponses match? " + isOK);

		return isOK;
	}

	/* Helper method to compute prover responses */
	private String computeProverResponses() {
		HashMap<String, byte[][]> openings = VerifierProxy.getInstance().getOpenings();

		String[] proxyOffsets = new String[users.length - 2];
		for (int i = 0; i < proxyOffsets.length; i++) {
			proxyOffsets[i] = new String(openings.get(users[i + 1])[1]);
		}

		String responseI = null;
		String offsetBitI = null;
		String proverResponses = "";
		for (int i = 0; i < this.getN(); i++) {
			responseI = response[i];
			for (int j = proxyOffsets.length - 1; j >= 0; j--) {
				offsetBitI = MHDEXor.bitAt(proxyOffsets[j], i);
				responseI = MHDEXor.xorBits(responseI, offsetBitI);
			}
			proverResponses = proverResponses.concat(responseI);
		}

		return proverResponses.trim();
	}

	/* helper method to validate the prover */
	private boolean validateProver() {
		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		VerifierProxy vProxy = VerifierProxy.getInstance();
		PublicKey signPK = ttp.getUserPublicKey_Sign("U");
		String transcript = this.computeTranscript();

		byte[] commit = vProxy.getCommits().get("U");
		byte[] signedCommit = vProxy.getSignedCommits().get("U");
		byte[] encryptedR = vProxy.getOpenings().get("U")[0];
		byte[] signedEncryptedR = vProxy.getSignedOpenings().get("U")[0];
		byte[] decryptedR = MHDECipher.decryptWithRSA(encryptedR, encryptSK);
		byte[] concatenated_enR_tCript = MHDEXor.concat(encryptedR, transcript.getBytes());
		byte[] encryptedOffset = vProxy.getOpenings().get("U")[1];
		byte[] signedEncryptedOffset = vProxy.getSignedOpenings().get("U")[1];
		byte[] decryptedOffset = MHDECipher.decryptWithRSA(encryptedOffset, encryptSK);
		byte[] concatenated_enOff_tCript = MHDEXor.concat(encryptedOffset, transcript.getBytes());

		boolean verify_commit_sign = MHDESignature.verifyWithDSA(commit, signedCommit, signPK);
		boolean verify_r_sign = MHDESignature.verifyWithDSA(concatenated_enR_tCript, signedEncryptedR, signPK);
		boolean verify_offset_sign = MHDESignature.verifyWithDSA(concatenated_enOff_tCript, signedEncryptedOffset,
				signPK);
		boolean verify_open_commit = MHDECommitment.verifyWithPederson(decryptedR, decryptedOffset, commit);

		boolean isProverHonest = false;

		if (verify_commit_sign && verify_r_sign && verify_offset_sign && verify_open_commit) {
			System.out.println("Prover is honest");
			isProverHonest = true;
		} else {
			String response = "";
			if (!verify_commit_sign) {
				response = response.concat(";unmatched commit and sign");
			}
			if (!(verify_r_sign & verify_offset_sign)) {
				response = response.concat(";unmatched opening and sign");
			}
			if (!verify_open_commit) {
				response = response.concat(";unmatched commit and opening");
			}
			System.out.println("Prover is malicious(" + response + ")");
			isProverHonest = false;
		}

		return isProverHonest;
	}

	/*Helper method to compute the transcript*/
	private String computeTranscript() {
		String tString = "";
		for (int i = 0; i < this.getN(); i++) {
			tString = tString.concat(challenge[i]);
			tString = tString.concat(MHDEXor.bitAt(proverResponses, i));
		}
		return tString.trim();
	}

}
