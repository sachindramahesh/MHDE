/**
 * Proxy.java - The concrete class that extends the ProverOrProxy abstract class. Used to
 * create intermediate proxy objects. Overrides the run() method from Runnable interface to enable
 * an object of this class to run in its own thread.
 *  
 * @author Mahesh S. Perera
 */

package thesis.mhde.element;

import java.security.KeyPair;
import java.security.PublicKey;
import thesis.mhde.crypto.MHDESignature;
import thesis.mhde.crypto.MHDEXor;

public class Proxy extends ProverOrProxy {

	public Proxy(String nodeName, Link leftLink, Link rightLink, int n, KeyPair signKP) {
		super(nodeName, leftLink, rightLink, n, signKP);
	}

	@Override
	/*Overrided run method*/
	public void run() {

		this.selectAndRun(0, 1, -1);

		for (int i = 0; i < this.getN(); i++) {
			this.selectAndRun(2, 3, i);
		}

		this.selectAndRun(-1, 4, -1);

	}

	/*helper method to select and run the correct phase of the protocol*/
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

	/*
	 * Executes the phase-0 of the MHDE protocol. Verifies the path signed by
	 * the verifier
	 */
	private void phaseZero() {// method-#0

		byte[][] data = this.getRightLink().getPhase0_data();
		byte[] path = data[0];
		byte[] sign = data[1];
		PublicKey pk = TrustedThirdParty.getVerifierPublicKey_Sign();
		boolean verifies = MHDESignature.verifyWithDSA(path, sign, pk);
		System.out.println(this.getNodeName() + " " + verifies);
		
		this.getLeftLink().setPhase0_data(path, sign);
	}

	/*
	 * Executes the phase-1 of the MHDE protocol. Selects a random n-bit offset,
	 * commit it, sign it and send the commitment and signature to the verifier
	 */
	private void phaseOne() {// method-#1

		this.setOffset();
		this.commitOffset();
		this.signCommitment();
		this.sendCommitAndSignature();

		//System.out.println(this.getNodeName() + "'s offset " + this.getOffset());
	}

	/*
	 * Executes the first part of the phase-2 of the MHDE protocol. Relay the
	 * verifier's challenge to the next node in the path towards the prover's
	 * side
	 */
	private void phaseTwo_first() {// method-#2
		Link r_link = this.getRightLink();
		Link l_link = this.getLeftLink();
		String challenge = r_link.getChallenge();
		l_link.setChallenge(challenge);
		l_link.setTimer(r_link.getTimer() + l_link.getDelay());
	}

	/*
	 * Executes the second part of the phase-3 of the MHDE protocol. Xor this
	 * user's offset-bit corresponding to the given round with the bit got from
	 * the previous user and send the result to next user towards the verifier's
	 * side
	 */
	private void phaseTwo_second(int round) {// method-#3
		Link r_link = this.getRightLink();
		Link l_link = this.getLeftLink();
		String challenge = l_link.getResponse();
		String offsetBit = MHDEXor.bitAt(this.getOffset(), round);
		String response = MHDEXor.xorBits(challenge, offsetBit);
		r_link.setResponse(response);
		r_link.setTimer(l_link.getTimer() + r_link.getDelay());
	}

	/*
	 * Executes the phase-3 of the MHDE protocol. Set the opening, sign it and
	 * send both the opening and the signature to the verifier
	 */
	private void phaseThree() {// method-#4
		this.setOpening();
		this.setSignedOpening();
		this.sendOpeningAndSignature();
	}

}
