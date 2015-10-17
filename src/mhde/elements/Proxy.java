package mhde.elements;

import java.security.KeyPair;
import java.security.PublicKey;

public class Proxy extends Node implements Runnable {

	private Link l_link;
	private Link r_link;
	private int rounds;
	private String name;

	public Proxy(String name, Link leftLink, Link rightLink, KeyPair kp, int n) {
		super(name, leftLink, rightLink, kp, n);
		this.l_link = leftLink;
		this.r_link = rightLink;
		this.rounds = n;
		this.name = name;
	}

	public void run() {

		this.selectAndRun(0, 1, -1);

		for (int i = 0; i < rounds; i++) {
			this.selectAndRun(2, 3, i);
		}

		this.selectAndRun(-1, 4, -1);

	}

	private void selectAndRun(int methodOne, int methodTwo, int r) {
		synchronized (r_link) {
			if (!r_link.getFlag().equals(this.getName())) {
				try {
					r_link.wait();
				} catch (InterruptedException e) {
				}
			}
			synchronized (l_link) {
				switch (methodOne) {
				case 0:
					this.phaseZero();
					break;
				case 2:
					this.phaseTwo_first();
					break;
				default:
					break;
				}
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
				switch (methodTwo) {
				case 1:
					this.phaseOne();
					break;
				case 3:
					this.phaseTwo_second(r);
					break;
				case 4:
					this.phaseThree();
					break;
				default:
					break;
				}
				r_link.setFlag(r_link.getRightNode());
				r_link.notify();
			}
		}

	}

	private void phaseZero() {// method-#0

		byte[][] data = r_link.getPhase0_data();
		byte[] path = data[0];
		byte[] sign = data[1];
		PublicKey pk = TrustedThirdParty.getVerifierPublicKey_Sign();

		boolean verifies = this.verifyData(path, sign, pk);
		System.out.println(this.name + " " + verifies);
		l_link.setPhase0_data(path, sign);

	}

	private void phaseOne() {// method-#1

		this.setN_bitString(this.getN());
		this.setOffset();
		this.doCommit();
		this.signCommit();
		this.sendCommitAndSignature();

		System.out.println(this.name + "'s offset " + this.getN_bitString());

	}

	private void phaseTwo_first() {// method-#2

		String challenge = r_link.getChallenge();
		l_link.setChallenge(challenge);
		this.delay();
	}

	private void phaseTwo_second(int round) {// method-#3

		String challenge = l_link.getResponse();
		String offsetBit = this.bitAt(this.getN_bitString(), round);
		String response = this.xorBits(challenge, offsetBit);
		r_link.setResponse(response);
		this.delay();
	}

	private void phaseThree() {// method-#4
		this.setOpening();
		this.setSignedOpening();
		this.sendOpeningAndSignature();
	}

}
