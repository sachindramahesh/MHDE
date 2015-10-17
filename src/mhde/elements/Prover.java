package mhde.elements;

import java.security.KeyPair;
import java.security.PublicKey;

public class Prover extends Node implements Runnable {

	private Link r_Link;
	private String secretKey_K;
	private int rounds;

	private String[] challenge;
	private String[] response;
	private String[] transcript;
	private String transcriptString;

	public Prover(String name, Link rightLink, KeyPair kp, int n, String k) {
		super(name, null, rightLink, kp, n);
		this.r_Link = rightLink;
		this.secretKey_K = k;
		this.rounds = n;
		this.challenge = new String[n];
		this.response = new String[n];
		this.transcript = new String[2 * n];

		System.out.println(name + "'s n-bit secret " + this.secretKey_K);
	}

	public void run() {
		synchronized (r_Link) {
			if (!r_Link.getFlag().equals(this.getName())) {
				try {
					r_Link.wait();
				} catch (InterruptedException e) {
				}
			}
			this.phaseZero();
			this.phaseOne();
			r_Link.setFlag(r_Link.getRightNode());
			r_Link.notify();
		}

		for (int i = 0; i < rounds; i++) {
			synchronized (r_Link) {
				if (!r_Link.getFlag().equals(this.getName())) {
					try {
						r_Link.wait();
					} catch (InterruptedException e) {
					}
				}
				this.phaseTwo(i);
				r_Link.setFlag(r_Link.getRightNode());

				r_Link.notify();
			}
		}

		synchronized (r_Link) {
			if (!r_Link.getFlag().equals(this.getName())) {
				try {
					r_Link.wait();
				} catch (InterruptedException e) {
				}
			}
			this.phaseThree();
			r_Link.setFlag(r_Link.getRightNode());
			r_Link.notify();
		}

	}

	public void phaseZero() {

		byte[][] data = r_Link.getPhase0_data();
		byte[] path = data[0];
		byte[] sign = data[1];
		PublicKey pk = TrustedThirdParty.getVerifierPublicKey_Sign();

		boolean verifies = this.verifyData(path, sign, pk);
		System.out.println(this.getName() + " " + verifies);

		System.out
				.println("---------------------PHASE-0 COMPLETED----------------- ");

	}

	public void phaseOne() {
		System.out
				.println("---------------------PHASE-I STARTED----------------- ");
		this.setN_bitString(this.getN());
		this.setOffset();
		this.doCommit();
		this.signCommit();
		this.sendCommitAndSignature();

		System.out.println(this.getName() + "'s n-bit offset string "
				+ this.getN_bitString());

	}

	public void phaseTwo(int round) {

		String offsetBit = this.bitAt(this.getN_bitString(), round);
		String challengeBit = this.getRightLink().getChallenge();// how to use
																	// challenge
																	// bit
		this.challenge[round] = challengeBit;

		String resp = "";

		if (challengeBit.equals("0")) {
			resp = offsetBit;
		} else if (challengeBit.equals("1")) {
			String secretKeyBit = this.bitAt(secretKey_K, round);
			resp = this.xorBits(offsetBit, secretKeyBit);
		}

		this.response[round] = resp;
		this.getRightLink().setResponse(resp);

		try {
			Thread.sleep(1000);
			System.out.println("delayed 1000ms by " + this.getName());
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

	}

	public void phaseThree() {
		this.setOpening();
		this.setSignedOpening();
		this.sendOpeningAndSignature();
	}

	public void setOpening() {

		byte[] tempOpening = this.encryptData(this.getOffset(),
				TrustedThirdParty.getVerifierPublicKey_Encrypt());
		this.setOpening(tempOpening);
	}

	public void setSignedOpening() {

		for (int i = 0; i < rounds; i++) {
			transcript[2 * i] = challenge[i];
			transcript[(2 * i) + 1] = response[i];
		}

		String temp = "";

		for (String b : transcript) {
			temp = temp.concat(b);
		}

		transcriptString = temp;
		System.out.println("Transcript string at Prover = " + transcriptString);

		byte[] openingBytes = this.getOpening();
		byte[] transcriptBytes = transcriptString.getBytes();
		byte[] concatenation = new byte[openingBytes.length
				+ transcriptBytes.length];

		for (int i = 0; i < concatenation.length; i++) {
			concatenation[i] = i < openingBytes.length ? openingBytes[i]
					: transcriptBytes[i - openingBytes.length];
		}

		this.setSignedOpening(this.signData(concatenation));

	}

}
