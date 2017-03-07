package thesis.mhde.element;

import java.security.KeyPair;
import java.security.PublicKey;
import thesis.mhde.crypto.MHDESignature;
import thesis.mhde.crypto.MHDEXor;

public class Proxy extends ProverOrProxy{

	public Proxy(String nodeName, Link leftLink, Link rightLink, int n, KeyPair signKP) {
		super(nodeName, leftLink, rightLink, n, signKP);
	}

	@Override
	public void run() {

		this.selectAndRun(0, 1, -1);

		for (int i = 0; i < this.getN(); i++) {
			this.selectAndRun(2, 3, i);
		}

		this.selectAndRun(-1, 4, -1);

	}

	private void selectAndRun(int methodOne, int methodTwo, int r) {
		Link r_link = this.getRightLink();
		Link l_link = this.getLeftLink();
		synchronized (r_link) {
			if (!r_link.getFlag().equals(this.getNodeName())) {
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
					this.applyDelay(r_link.getDelay());
					this.phaseTwo_first();
					break;
				default:
					break;
				}
				l_link.setFlag(l_link.getLeftNode());
				l_link.notify();
			}
			synchronized (l_link) {
				if (!l_link.getFlag().equals(this.getNodeName())) {
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
					this.applyDelay(r_link.getDelay());
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

		byte[][] data = this.getRightLink().getPhase0_data();
		byte[] path = data[0];
		byte[] sign = data[1];
		PublicKey pk = TrustedThirdParty.getVerifierPublicKey_Sign();

		boolean verifies = MHDESignature.verifyWithDSA(path, sign, pk);
		System.out.println(this.getNodeName() + " " + verifies);
		this.getLeftLink().setPhase0_data(path, sign);

	}

	private void phaseOne() {// method-#1

		this.setOffset();
		this.commitOffset();
		this.signCommitment();
		this.sendCommitAndSignature();

		System.out.println(this.getNodeName() + "'s offset " + this.getOffset());

	}

	private void phaseTwo_first() {// method-#2
		Link r_link = this.getRightLink();
		Link l_link = this.getLeftLink();
		String challenge = r_link.getChallenge();
		l_link.setChallenge(challenge);
		l_link.setTimer(r_link.getTimer() + l_link.getDelay());
	}

	private void phaseTwo_second(int round) {// method-#3
		Link r_link = this.getRightLink();
		Link l_link = this.getLeftLink();
		String challenge = l_link.getResponse();
		String offsetBit = MHDEXor.bitAt(this.getOffset(), round);
		String response = MHDEXor.xorBits(challenge, offsetBit);
		r_link.setResponse(response);
		r_link.setTimer(l_link.getTimer() + r_link.getDelay());
	}

	private void phaseThree() {// method-#4
		this.setOpening();
		this.setSignedOpening();
		this.sendOpeningAndSignature();
	}

}
