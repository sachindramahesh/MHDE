/**
 * Prover.java - The concrete class that extends ProverOrProxyClass to implement
 * the functionalities of the Prover
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.element;

import java.security.KeyPair;
import java.security.PublicKey;
import thesis.mhde.crypto.MHDECipher;
import thesis.mhde.crypto.MHDESignature;
import thesis.mhde.crypto.MHDEXor;

public class Prover extends ProverOrProxy {

	private String secretKey_K;// secret key K shared between the prover and the
								// verifier
	private String[] challenge;// challenge as received from the verifier
	private String[] response;// response as computed by the prover

	public Prover(String nodeName, Link rightLink, int n, KeyPair signKP, String sk_K) {
		super(nodeName, null, rightLink, n, signKP);
		this.challenge = new String[n];
		this.response = new String[n];
		this.secretKey_K = sk_K;
	}

	@Override
	/* Overrided run method that defines the thread specific behaviour */
	public void run() {
		this.selectAndRun(0, -1);

		for (int i = 0; i < this.getN(); i++) {

			this.selectAndRun(1, i);
		}

		this.selectAndRun(2, -1);

	}

	/*
	 * helper method of run method to select and run the correct phase of the
	 * protocol
	 */
	private void selectAndRun(int method, int r) {
		Link r_Link = this.getRightLink();
		synchronized (r_Link) {
			if (!r_Link.getFlag().equals(this.getNodeName())) {
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

		System.out.println("\t====PHASE-0 COMPLETED====\n\n ");
	}

	/*
	 * Executes the phase-1 of the MHDE protocol. Selects a random n-bit offset,
	 * commit it, sign it and send the commitment and signature to the verifier
	 */
	private void phaseOne() {// method-#0
		System.out.println("\t====PHASE-I STARTED==== ");
		this.setOffset();
		this.commitOffset();
		this.signCommitment();
		this.sendCommitAndSignature();

		System.out.println(this.getNodeName() + "'s offset " + this.getOffset());

	}

	/*
	 * Executes the phase-2 of the MHDE protocol. Calculate the response based
	 * on the verifier's challenge
	 */
	private void phaseTwo(int round) {// method-#1

		Link r_Link = this.getRightLink();
		String offsetBit = MHDEXor.bitAt(this.getOffset(), round);
		String challengeBit = r_Link.getChallenge();
		this.challenge[round] = challengeBit;

		String resp = "";

		if (challengeBit.equals("0")) {
			resp = offsetBit;
		} else if (challengeBit.equals("1")) {
			String secretKeyBit = MHDEXor.bitAt(secretKey_K, round);
			resp = MHDEXor.xorBits(offsetBit, secretKeyBit);
		}

		this.response[round] = resp;
		r_Link.setResponse(resp);
		r_Link.setTimer(r_Link.getTimer() + r_Link.getDelay());

	}

	/*
	 * Executes the phase-3 of the protocol. The way the prover sign the opening
	 * is different from the way proxies sign openings
	 */
	private void phaseThree() {// method-#2

		this.sendOpeningAndSignature();

	}

	private byte[] computeTranscript() {
		String tString = "";
		for (int i = 0; i < this.getN(); i++) {

			tString = tString.concat(challenge[i]);
			tString = tString.concat(response[i]);
		}
		return tString.trim().getBytes();
	}

	@Override
	public void sendOpeningAndSignature() {
		VerifierProxy vProxy = VerifierProxy.getInstance();

		PublicKey epk = TrustedThirdParty.getVerifierPublicKey_Encrypt();
		byte[] encryptedR = MHDECipher.encryptWithRSA(this.getR(), epk);
		byte[] encryptedOffset = MHDECipher.encryptWithRSA(this.getOffsetInBytes(), epk);
		this.setOpening(encryptedR, encryptedOffset);
		vProxy.updateOpenings(this.getNodeName(), this.getOpening());

		byte[] transcriptBytes = this.computeTranscript();
		byte[] concat_R_Transcript = MHDEXor.concat(encryptedR, transcriptBytes);
		byte[] concat_Offset_Transcript = MHDEXor.concat(encryptedOffset, transcriptBytes);
		byte[] signedConcatR = MHDESignature.signWithDSA(concat_R_Transcript, this.getSignSK());
		byte[] signedConcatOffset = MHDESignature.signWithDSA(concat_Offset_Transcript, this.getSignSK());
		this.setSignedOpening(signedConcatR, signedConcatOffset);
		vProxy.updateSignedOpenings(this.getNodeName(), this.getSignedOpening());
	}

}
