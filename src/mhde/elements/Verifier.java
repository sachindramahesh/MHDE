package mhde.elements;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.HashMap;

public class Verifier extends Node implements Runnable {

	public static int start = 0;

	private String path;
	private String[] users;

	private String[] challenge;
	private String[] response;
	private String[] proverResponse;
	private String[] transcript;
	private String transcriptString;
	private long[] timeLapse;
	// private times[]

	private String secretKey_K;

	private PrivateKey esk;

	public Verifier(String name, Link leftLink, KeyPair kp, String path, int n,
			String k, PrivateKey esk) {
		super(name, leftLink, null, kp, n);
		this.path = path;
		this.challenge = new String[n];
		this.response = new String[n];
		this.proverResponse = new String[n];
		this.timeLapse = new long[n];
		this.transcript = new String[2 * n];
		this.secretKey_K = k;
		this.esk = esk;
		users = path.split("\\s*,\\s*");

		System.out.println(this.getName() + "'s n-bit secret "
				+ this.secretKey_K);
	}

	public void run() {
		Link leftLink = this.getLeftLink();
		long startClock = 0;
		long endClock = 0;

		synchronized (leftLink) {
			this.phaseZero();
			leftLink.setFlag(leftLink.getLeftNode());
			leftLink.notify();
		}

		int rounds = this.getN();

		for (int i = 0; i < rounds; i++) {
			synchronized (leftLink) {
				if (!leftLink.getFlag().equals(this.getName())) {
					try {
						leftLink.wait();
					} catch (InterruptedException e) {
					}
				}
				if (i == 0) {
					this.phaseOne();
				}
				if (i > 0) {
					this.response[i - 1] = this.getLeftLink().getResponse();
					endClock = System.nanoTime();

					timeLapse[i - 1] = endClock - startClock;
					System.out.println(this.getName() + " @round=" + (i - 1)
							+ " challenge=" + challenge[i - 1] + " response="
							+ this.response[i - 1] + " lapsed time = "
							+ this.timeLapse[i - 1] + "ns");

				}
				this.phaseTwo(i);
				leftLink.setFlag(leftLink.getLeftNode());
				startClock = System.nanoTime();
				leftLink.notify();
			}

		}

		synchronized (leftLink) {
			if (!leftLink.getFlag().equals(this.getName())) {
				try {
					leftLink.wait();
				} catch (InterruptedException e) {
				}
			}
			this.response[rounds - 1] = leftLink.getResponse();
			endClock = System.nanoTime();
			this.timeLapse[rounds - 1] = endClock - startClock;
			System.out.println(this.getName() + " @round=" + (rounds - 1)
					+ " challenge=" + challenge[rounds - 1] + " response="
					+ this.response[rounds - 1] + " lapsed time = "
					+ this.timeLapse[rounds - 1] + "ns");

			System.out
					.println("---------------------PHASE-II COMPLETED----------------- ");

			System.out
					.println("---------------------PHASE-III STARTED----------------- ");

			// this.phaseThreeDummy();

			leftLink.setFlag(leftLink.getLeftNode());
			leftLink.notify();

		}

		synchronized (leftLink) {
			if (!leftLink.getFlag().equals(this.getName())) {
				try {
					leftLink.wait();
				} catch (InterruptedException e) {
				}
			}

			this.phaseThree();

		}

		synchronized (this) {
			this.notify();
		}

	}

	public void phaseZero() {
		Link leftLink = this.getLeftLink();

		leftLink.setData_0(start);

		byte[] sign = this.signData(path.getBytes());
		leftLink.setPhase0_data(path.getBytes());
		leftLink.setPhase0_sign(sign);

		System.out
				.println("---------------------PHASE-0 STARTED----------------- ");

	}

	public void phaseOne() {

		System.out
				.println("---------------------PHASE-I COMPLETED----------------- ");
		System.out
				.println("---------------------PHASE-II STARTED----------------- ");

	}

	public void phaseTwo(int round) {

		int temp = this.getLeftLink().getData_0();
		temp++;
		this.getLeftLink().setData_0(temp);

		String challenge = RandomNumberGenerator.getInstance()
				.nextRandomNumber(1);
		this.challenge[round] = challenge;
		this.getLeftLink().setChallenge(challenge);

	}

	public void phaseThreeDummy() {
		System.out.println("--------------------------------");
		System.out.println(this.getLeftLink().getData_0());
		System.out.println("--------------------------------");
		start = this.getLeftLink().getData_0();

	}

	public void phaseThree() {

		this.validateOpeningAndSignatures();
		this.validateChallengeAndResponses();
		this.validateCommitmentAndSignatures();
		this.validateOpeningsAndCommitments();

	}

	private void validateOpeningAndSignatures() {
		System.out.println("->->->->->->Validating Openings and Signatures");
		TrustedThirdParty ttp = TrustedThirdParty.getInstance();

		HashMap<String, byte[]> openings = ttp.getOpenings();
		HashMap<String, byte[]> signedOpenings = ttp.getSignedOpenings();

		boolean isOK = false;

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
				System.out.println("Node=U, Opening= " + new String(open)
						+ ", is opening signature valid = " + isOK);

			} else {
				byte[] open = openings.get(user);
				isOK = this.verifyData(openings.get(user),
						signedOpenings.get(user),
						ttp.getUserPublicKey_Sign(user));
				System.out.println("Node=" + user + ", Opening= "
						+ new String(open) + ", is opening signature valid = "
						+ isOK);

			}
		}

		System.out
				.println("->->->->->->Validating Openings and Signatures DONE!!!");

	}

	private void validateChallengeAndResponses() {
		int rounds = this.getN();
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
		System.out.println("is prover offset valid?= " + isOK);

	}

	private void validateCommitmentAndSignatures() {
		System.out.println("->->->->->->Validating Commitments and Signatures");
		TrustedThirdParty ttp = TrustedThirdParty.getInstance();

		HashMap<String, byte[]> commits = ttp.getCommits();
		HashMap<String, byte[]> signedCommits = ttp.getSignedCommits();

		boolean isOK = false;

		for (int i = 0; i < users.length - 1; i++) {
			String user = users[i];

			isOK = this.verifyData(commits.get(user), signedCommits.get(user),
					ttp.getUserPublicKey_Sign(user));
			System.out.println("Node=" + user
					+ ", is commitment signature valid = " + isOK);

		}

		System.out
				.println("->->->->->->Validating Commitment and Signatures DONE!!!");

	}

	private void validateOpeningsAndCommitments() {
		System.out.println("->->->->->->Validating Openings and Commitments");
		TrustedThirdParty ttp = TrustedThirdParty.getInstance();

		HashMap<String, byte[]> openings = ttp.getOpenings();
		HashMap<String, byte[]> commits = ttp.getCommits();

		boolean isOK = false;

		for (int i = 0; i < users.length - 1; i++) {
			String user = users[i];
			if (user.equals("U")) {

				byte[] open = this.decryptData(openings.get(user), esk);
				isOK = this.checkCommit(open, commits.get(user));
				System.out
						.println("Node=U does opening and commitment match? = "
								+ isOK);

			} else {

				isOK = this.checkCommit(openings.get(user), commits.get(user));
				System.out.println("Node=" + user
						+ " does opening and commitment match? = " + isOK);
			}
		}

		System.out
				.println("->->->->->->Validating Openings and Commitments DONE!!!");

	}

	public boolean checkCommit(byte[] opening, byte[] commit) {
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

		int rounds = this.getN();

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
		int rounds = this.getN();

		for (int i = 0; i < rounds; i++) {
			transcript[2 * i] = challenge[i];
			transcript[(2 * i) + 1] = proverResponse[i];
		}

		String temp = "";

		for (String b : transcript) {
			temp = temp.concat(b);
		}

		transcriptString = temp;
		System.out
				.println("Transcript string at verifier= " + transcriptString);

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
