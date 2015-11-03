package mhde.elements;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.HashMap;

public class Verifier extends Node implements Runnable {

	private String name;
	private Link l_link;
	private int rounds;

	private String path;
	private String[] users;

	private String[] challenge;
	private String[] response;
	private long[] timeLapse;

	private String[] proverResponse;
	private String[] proverTranscript;
	private String transcriptString;

	private String secretKey_K;// shared secret between prover and verifier
	private PrivateKey esk;// verifier's private key
	
	private String pathNum;

	public Verifier(String name, Link leftLink, KeyPair kp, String path, int n,
			String k, PrivateKey esk, String pathNum) {
		super(name, leftLink, null, kp, n);
		this.name = name;
		this.l_link = leftLink;
		this.rounds = n;
		this.path = path;
		this.users = path.split("\\s*,\\s*");
		this.challenge = new String[n];
		this.response = new String[n];
		this.timeLapse = new long[n+1];
		timeLapse[n]=this.users.length;//length of the path
		this.proverResponse = new String[n];
		this.proverTranscript = new String[2 * n];
		this.transcriptString = "";
		this.secretKey_K = k;
		this.esk = esk;
		this.pathNum=pathNum;

		System.out.println(name + "'s n-bit secret " + secretKey_K);

	}

	public void run() {
		long startClock = 0;
		long endClock = 0;

		synchronized (l_link) {
			this.phaseZero();
			l_link.setFlag(l_link.getLeftNode());
			l_link.notify();
		}

		for (int i = 0; i < rounds; i++) {
			synchronized (l_link) {
				if (!l_link.getFlag().equals(this.name)) {
					try {
						l_link.wait();
					} catch (InterruptedException e) {
					}
				}
				if (i == 0) {
					this.phaseOne();
				} else if (i > 0) {
					endClock = System.nanoTime();
					this.response[i - 1] = l_link.getResponse();					
					timeLapse[i - 1] = endClock - startClock;
					System.out.println(name + " @round=" + (i - 1)
							+ " challenge=" + challenge[i - 1] + " response="
							+ response[i - 1] + " lapsed time = "
							+ timeLapse[i - 1] + "ns");

				}
				this.phaseTwo(i);

				l_link.setFlag(l_link.getLeftNode());				
				l_link.notify();
				startClock = System.nanoTime();
			}
		}

		synchronized (l_link) {
			if (!l_link.getFlag().equals(this.name)) {
				try {
					l_link.wait();
				} catch (InterruptedException e) {
				}
			}
			this.response[rounds - 1] = l_link.getResponse();
			endClock = System.nanoTime();
			this.timeLapse[rounds - 1] = endClock - startClock;
			System.out.println(name + " @round=" + (rounds - 1) + " challenge="
					+ challenge[rounds - 1] + " response="
					+ response[rounds - 1] + " lapsed time = "
					+ timeLapse[rounds - 1] + "ns");

			System.out.println("\t====PHASE-II COMPLETED====\n\n ");
			System.out.println("\t====PHASE-III STARTED==== ");

			l_link.setFlag(l_link.getLeftNode());
			l_link.notify();
		}

		synchronized (l_link) {
			if (!l_link.getFlag().equals(this.getName())) {
				try {
					l_link.wait();
				} catch (InterruptedException e) {
				}
			}
			this.phaseThree();
		}

		synchronized (this) {// notify to proceed to next path
			this.notify();
		}

	}

	private void phaseZero() {

		byte[] sign = this.signData(path.getBytes());
		l_link.setPhase0_data(path.getBytes(), sign);
		System.out.println("\t====PHASE-0 STARTED==== ");

	}

	private void phaseOne() {

		System.out.println("\t====PHASE-I COMPLETED====\n\n");
		System.out.println("\t====PHASE-II STARTED==== ");

	}

	private void phaseTwo(int round) {

		String challenge = RandomNumberGenerator.getInstance()
				.nextRandomNumber(1);
		this.challenge[round] = challenge;
		l_link.setChallenge(challenge);

	}

	public void phaseThree() {
		
		TrustedThirdParty.setTiming(pathNum, timeLapse);

		int unmatchedOpeningsandSigns = this.validateOpeningAndSignatures();
		boolean isChallengeResponsesConsistent = this
				.validateChallengeAndResponses();
		int unmatchedCommitmentsandSigns = this
				.validateCommitmentAndSignatures();
		int unmatchedOpeningsandCommits = this.validateOpeningsAndCommitments();
		if (unmatchedOpeningsandSigns == 0 && isChallengeResponsesConsistent
				&& unmatchedCommitmentsandSigns == 0
				&& unmatchedOpeningsandCommits == 0) {
			TrustedThirdParty.updateAuthentication(new Boolean(true));
			System.out.println("AUTHENTICATION BIT = 1");
		} else {
			if (unmatchedOpeningsandSigns > 0) {
				System.out.println("There are " + unmatchedOpeningsandSigns
						+ " unmatched openings and signatures");
			}
			if (unmatchedCommitmentsandSigns > 0) {
				System.out.println("There are " + unmatchedCommitmentsandSigns
						+ " unmatched commitments and signatures");
			}
			if (unmatchedOpeningsandCommits > 0) {
				System.out.println("There are " + unmatchedOpeningsandCommits
						+ " unmatched openings and commitments");
			}
			if (!isChallengeResponsesConsistent) {
				System.out
						.println("There are inconsistent challenges and responses");
			}
			TrustedThirdParty.updateAuthentication(new Boolean(false));
			System.out.println("AUTHENTICATION BIT = 0");
		}

	}

	private int validateOpeningAndSignatures() {

		System.out.println("\n->->->->->->Validating Openings and Signatures");

		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		HashMap<String, byte[]> openings = ttp.getOpenings();
		HashMap<String, byte[]> signedOpenings = ttp.getSignedOpenings();

		boolean isOK = false;
		int falseCount = 0;

		for (int i = 0; i < users.length - 1; i++) {
			String user = users[i];
			if (user.equals("U")) {
				this.constructProverResponses(openings);
				this.constructTranscript();
				byte[] open = this.decryptData(openings.get(user), esk);
				isOK = this.verifyData(
						this.constructProverOpening(openings.get(user)),
						signedOpenings.get(user),
						ttp.getUserPublicKey_Sign(user));
				if (!isOK) {
					falseCount++;
				}
//				System.out.println("Node=U, Opening= " + new String(open)
//						+ ", is opening signature valid = " + isOK);

			} else {
				byte[] open = openings.get(user);
				isOK = this.verifyData(open, signedOpenings.get(user),
						ttp.getUserPublicKey_Sign(user));
				if (!isOK) {
					falseCount++;
				}
//				System.out.println("Node=" + user + ", Opening= "
//						+ new String(open) + ", is opening signature valid = "
//						+ isOK);
			}
		}

		System.out.println("False count=" + falseCount);

		return falseCount;

	}

	private boolean validateChallengeAndResponses() {
		String proverOffset = "";

		for (int i = 0; i < rounds; i++) {
			if (challenge[i].equals("0")) {
				proverOffset = proverOffset.concat(proverResponse[i]);
			} else if (challenge[i].equals("1")) {
				String secretKeyBit = this.bitAt(secretKey_K, i);
				proverOffset = proverOffset.concat(this.xorBits(
						proverResponse[i], secretKeyBit));
			}
		}

		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		HashMap<String, byte[]> openings = ttp.getOpenings();
		String open = new String(this.decryptData(openings.get("U"), esk));

		boolean isOK = open.equals(proverOffset);
		//System.out.println("is prover offset valid?= " + isOK);

		return isOK;

	}

	private int validateCommitmentAndSignatures() {

		System.out
				.println("\n->->->->->->Validating Commitments and Signatures");

		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		HashMap<String, byte[]> commits = ttp.getCommits();
		HashMap<String, byte[]> signedCommits = ttp.getSignedCommits();

		boolean isOK = false;
		int falseCount = 0;

		for (int i = 0; i < users.length - 1; i++) {
			String user = users[i];
			isOK = this.verifyData(commits.get(user), signedCommits.get(user),
					ttp.getUserPublicKey_Sign(user));
			if (!isOK) {
				falseCount++;
			}
//			System.out.println("Node=" + user
//					+ ", is commitment signature valid = " + isOK);
		}

		System.out.println("False count=" + falseCount);

		return falseCount;

	}

	private int validateOpeningsAndCommitments() {

		System.out.println("\n->->->->->->Validating Openings and Commitments");

		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		HashMap<String, byte[]> openings = ttp.getOpenings();
		HashMap<String, byte[]> commits = ttp.getCommits();

		boolean isOK = false;
		int falseCount = 0;

		for (int i = 0; i < users.length - 1; i++) {
			String user = users[i];
			if (user.equals("U")) {
				byte[] open = this.decryptData(openings.get(user), esk);
				isOK = this.checkCommit(open, commits.get(user));
				if (!isOK) {
					falseCount++;
				}
//				System.out
//						.println("Node=U does opening and commitment match? = "
//								+ isOK);
			} else {

				isOK = this.checkCommit(openings.get(user), commits.get(user));
				if (!isOK) {
					falseCount++;
				}
//				System.out.println("Node=" + user
//						+ " does opening and commitment match? = " + isOK);
			}
		}

		System.out.println("False count=" + falseCount);

		return falseCount;

	}

	private boolean checkCommit(byte[] opening, byte[] commit) {
		boolean isOK = false;
		try {
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			sha.update(opening);
			byte[] com = sha.digest();
			for (int i = 0; i < com.length; i++) {
				if (com[i] != commit[i]) {
					return false;
				}
			}
			isOK = true;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return isOK;
	}

	private void constructProverResponses(HashMap<String, byte[]> openings) {
		String[] offsets = new String[users.length - 1];
		for (int i = 1; i < offsets.length; i++) {
			offsets[i] = new String(openings.get(users[i]));
		}

		String xor = "";
		String pReponse = "";

		for (int i = 0; i < rounds; i++) {
			xor = this.xorBits(response[i],
					this.bitAt(offsets[offsets.length - 1], i));

			for (int j = offsets.length - 2; j >= 1; j--) {
				xor = this.xorBits(xor, this.bitAt(offsets[j], i));
			}
			proverResponse[i] = xor;
			pReponse = pReponse.concat(xor);
		}
		offsets[0] = pReponse.trim();

	}

	private void constructTranscript() {

		for (int i = 0; i < rounds; i++) {
			proverTranscript[2 * i] = challenge[i];
			proverTranscript[(2 * i) + 1] = proverResponse[i];
		}

		String temp = "";

		for (String b : proverTranscript) {
			temp = temp.concat(b);
		}

		transcriptString = temp;
//		System.out
//				.println("Transcript string at verifier= " + transcriptString);

	}

	private byte[] constructProverOpening(byte[] opening) {

		byte[] openingBytes = opening;
		byte[] transcriptBytes = transcriptString.getBytes();
		byte[] concatenation = new byte[openingBytes.length
				+ transcriptBytes.length];

		for (int i = 0; i < concatenation.length; i++) {
			concatenation[i] = i < openingBytes.length ? openingBytes[i]
					: transcriptBytes[i - openingBytes.length];
		}

		return concatenation;
	}

}
