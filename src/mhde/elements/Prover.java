package mhde.elements;

import java.security.KeyPair;
import java.security.PublicKey;

public class Prover extends Node implements Runnable {

	private String name;
	private Link r_Link;
	private int rounds;

	private String secretKey_K;

	private String[] challenge;
	private String[] response;
	private String[] transcript;
	
	//private long delay;

	public Prover(String name, Link rightLink, KeyPair kp, int n, String k) {
		super(name, null, rightLink, kp, n);
		this.name = name;
		this.r_Link = rightLink;
		this.rounds = n;
		this.secretKey_K = k;
		this.challenge = new String[n];
		this.response = new String[n];
		this.transcript = new String[2 * n];
		//this.delay=delay;

		System.out.println(name + "'s n-bit secret " + this.secretKey_K);

	}

	public void run() {

		this.selectAndRun(0, -1);

		for (int i = 0; i < this.rounds; i++) {

			this.selectAndRun(1, i);
		}

		this.selectAndRun(2, -1);

	}

	private void selectAndRun(int method, int r) {
		synchronized (r_Link) {
			if (!r_Link.getFlag().equals(this.name)) {
				try {
					r_Link.wait();
				} catch (InterruptedException e) {
				}
			}
			switch (method) {
			case 0:
				this.phaseZero();
				this.phaseOne();
				break;
			case 1:
				this.applyDelay(r_Link.getDelay());
				this.applyDelay(r_Link.getDelay());
				this.phaseTwo(r);
				break;
			case 2:
				this.phaseThree();
				break;
			default:
				break;
			}
			r_Link.setFlag(r_Link.getRightNode());
			r_Link.notify();
		}
	}

	private void phaseZero() {// method-#0

		byte[][] data = r_Link.getPhase0_data();
		byte[] path = data[0];
		byte[] sign = data[1];
		PublicKey pk = TrustedThirdParty.getVerifierPublicKey_Sign();
		boolean verifies = this.verifyData(path, sign, pk);

		System.out.println(this.name + " " + verifies);
		System.out.println("\t====PHASE-0 COMPLETED====\n\n ");

	}

	private void phaseOne() {// method-#0
		System.out.println("\t====PHASE-I STARTED==== ");
		this.setN_bitString(this.rounds);
		this.setOffset();
		this.doCommit();
		this.signCommit();
		this.sendCommitAndSignature();

		System.out.println(this.name +"'s offset "+ this.getN_bitString());

	}

	private void phaseTwo(int round) {// method-#1

		String offsetBit = this.bitAt(this.getN_bitString(), round);
		String challengeBit = r_Link.getChallenge();
		this.challenge[round] = challengeBit;

		String resp = "";

		if (challengeBit.equals("0")) {
			resp = offsetBit;
		} else if (challengeBit.equals("1")) {
			String secretKeyBit = this.bitAt(secretKey_K, round);
			resp = this.xorBits(offsetBit, secretKeyBit);
		}

		this.response[round] = resp;
		r_Link.setResponse(resp);

		

	}

	private void phaseThree() {// method-#2
		
		this.setOpening();
		this.setSignedOpening();
		this.sendOpeningAndSignature();
		
	}

	public void setOpening() {
		
		PublicKey pk=TrustedThirdParty.getVerifierPublicKey_Encrypt();
		byte[] tempOpening = this.encryptData(this.getOffset(),pk);
		this.setOpening(tempOpening);
		
	}

	public void setSignedOpening() {

		for (int i = 0; i < rounds; i++) {
			transcript[2 * i] = challenge[i];
			transcript[(2 * i) + 1] = response[i];
		}

		String tString = "";

		for (String b : transcript) {
			tString= tString.concat(b);
		}
	
		System.out.println("Transcript string at Prover = " + tString);

		byte[] openingBytes = this.getOpening();
		byte[] transcriptBytes = tString.getBytes();
		byte[] concatenation = new byte[openingBytes.length
				+ transcriptBytes.length];

		for (int i = 0; i < concatenation.length; i++) {
			concatenation[i] = i < openingBytes.length ? openingBytes[i]
					: transcriptBytes[i - openingBytes.length];
		}

		this.setSignedOpening(this.signData(concatenation));

	}

}
