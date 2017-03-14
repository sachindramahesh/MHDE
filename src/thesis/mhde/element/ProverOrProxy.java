/**
 * ProverOrProxy.java - An abstract class that extends BasicNode abstract class to provide 
 * further functionalities which are common for Prover and Proxy classes.
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.element;

import java.security.KeyPair;
import java.security.PrivateKey;

import thesis.mhde.crypto.MHDECommitment;
import thesis.mhde.crypto.MHDESignature;
import thesis.mhde.crypto.MHDERandomNumberGenerator;

public abstract class ProverOrProxy extends BasicNode {

	private PrivateKey signSK;// users private key for signing
	// during phase-1 offset(n-bit string) is selected.This is the message used
	// in the
	// Pederson commitment scheme. After committing offset(message) using
	// Pederson
	// {r,commitment} is outputted. The commitment is then signed
	private String offset;
	private byte[] offsetInBytes;
	private byte[] r;
	private byte[] commitment;
	private byte[] signedCommitment;
	// during phase-3 user has to send the opening and its signature. In
	// Pederson opening
	// is the couple {r,offset}. Signature is the couple gotten by
	// signing
	// {r,offset}.
	private byte[] signedOffset;
	private byte[] signedR;
	private byte[][] r_and_offset;
	private byte[][] r_and_offset_signed;

	public ProverOrProxy(String nodeName, Link leftLink, Link rightLink, int n, KeyPair signKP) {
		super(nodeName, leftLink, rightLink, n);
		this.signSK = signKP.getPrivate();
	}

	/**
	 * Returns this user's Private key used for signing
	 * 
	 * @return the signing private key
	 */
	public PrivateKey getSignSK() {
		return this.signSK;
	}

	/**
	 * Select and set a random n-bit offset string for this node. This method is
	 * used in phase-1 of the MHDE protocol
	 */
	public void setOffset() {
		this.offset = MHDERandomNumberGenerator.getNextRandomNumber(this.getN());
		this.offsetInBytes = this.offset.getBytes();
	}

	/**
	 * Returns this user's selected random n-bit offset string
	 * 
	 * @return the offset
	 */
	public String getOffset() {
		return this.offset;
	}

	/**
	 * Returns this user's offset as a byte array
	 * 
	 * @return offset in bytes
	 */
	public byte[] getOffsetInBytes() {
		return this.offsetInBytes;
	}

	/**
	 * Commits this node's offset using Pederson's scheme. This method is used
	 * in phase-1 of the MHDe protocol
	 */
	public void commitOffset() {
		byte[][] commit = MHDECommitment.commitWithPederson(offsetInBytes);
		this.r = commit[0];
		this.commitment = commit[1];
	}

	/**
	 * Returns the r-value chosen by this node during the commitment phase
	 * 
	 * @return r-value
	 */
	public byte[] getR() {
		return this.r;
	}

	/**
	 * Returns this node's commitment value of message as a byte array
	 * 
	 * @return the commitment
	 */
	public byte[] getCommitment() {
		return this.commitment;
	}

	/**
	 * Sign the commitment value using this node's private signing key. This
	 * method is used in the phase-1 of the MHDE protocol
	 */
	public void signCommitment() {
		this.signedCommitment = MHDESignature.signWithDSA(this.commitment, this.signSK);
	}

	/**
	 * Returns the signed commitment as a byte array
	 * 
	 * @return the signed commitment
	 */
	public byte[] getSignedCommit() {
		return this.signedCommitment;
	}

	/**
	 * Sends the commitment value and its signature to the verifier
	 */
	public void sendCommitAndSignature() {
		VerifierProxy vProxy = VerifierProxy.getInstance();
		vProxy.updateCommits(this.getNodeName(), this.commitment);
		vProxy.updateSignedCommits(this.getNodeName(), this.signedCommitment);
	}

	/**
	 * Sets the opening value for this node. Opening value is the pair r-value
	 * generated during the commitment phase and the offset value
	 */
	public void setOpening() {
		this.r_and_offset = new byte[][] { this.r, this.offsetInBytes };
	}

	/**
	 * Sets the opening value for this node using the given input parameters.
	 * Opening value is the pair r-value generated during the commitment phase
	 * and the offset value
	 * 
	 * @param r
	 *            r-value as a byte array
	 * @param offset
	 *            offset as a byte array
	 */
	public void setOpening(byte[] r, byte[] offset) {
		this.r_and_offset = new byte[][] { r, offset };
	}

	/**
	 * Returns the opening value pair {r-value,offset}
	 * 
	 * @return the opening value
	 */
	public byte[][] getOpening() {
		return this.r_and_offset;
	}

	/**
	 * Set the signed opening value. This is the pair obtained by signing
	 * r-value and offset separately
	 */
	public void setSignedOpening() {
		this.signedR = MHDESignature.signWithDSA(this.r, this.signSK);
		this.signedOffset = MHDESignature.signWithDSA(this.offsetInBytes, this.signSK);
		this.r_and_offset_signed = new byte[][] { this.signedR, this.signedOffset };
	}

	/**
	 * Set the signed opening value to the values given by the user.
	 * 
	 * @param signedR
	 *            the signature got by signing r-value
	 * @param signedOffset
	 *            the signature got by signing offset
	 */
	public void setSignedOpening(byte[] signedR, byte[] signedOffset) {
		this.r_and_offset_signed = new byte[][] { signedR, signedOffset };
	}

	/**
	 * Returns the pair signature of r-value and signature of offset
	 * 
	 * @return the signatures of r-value and offset
	 */
	public byte[][] getSignedOpening() {
		return this.r_and_offset_signed;
	}

	/**
	 * Sends the opening and signature of opening to the verifier
	 */
	public void sendOpeningAndSignature() {
		VerifierProxy vProxy = VerifierProxy.getInstance();
		vProxy.updateOpenings(this.getNodeName(), this.r_and_offset);
		vProxy.updateSignedOpenings(this.getNodeName(), this.r_and_offset_signed);
	}

	/**
	 * Make the current thread sleep for given number of milliseconds
	 * 
	 * @param delay
	 *            milliseconds to sleep this method
	 */
	public void applyDelay(int delay) {
		try {
			Thread.sleep(0, delay);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

}
