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

	public PrivateKey getSignSK() {
		return this.signSK;
	}

	public void setOffset() {
		this.offset = MHDERandomNumberGenerator.getNextRandomNumber(this.getN());
		this.offsetInBytes = this.offset.getBytes();
	}

	public String getOffset() {
		return this.offset;
	}

	public byte[] getOffsetInBytes() {
		return this.offsetInBytes;
	}

	public void commitOffset() {
		byte[][] commit = MHDECommitment.commitWithPederson(offsetInBytes);
		this.r = commit[0];
		this.commitment = commit[1];
	}

	public byte[] getR() {
		return this.r;
	}

	public byte[] getCommitment() {
		return this.commitment;
	}

	public void signCommitment() {
		this.signedCommitment = MHDESignature.signWithDSA(this.commitment, this.signSK);
	}

	public byte[] getSignedCommit() {
		return this.signedCommitment;
	}

	public void sendCommitAndSignature() {
		VerifierProxy vProxy = VerifierProxy.getInstance();
		vProxy.updateCommits(this.getNodeName(), this.commitment);
		vProxy.updateSignedCommits(this.getNodeName(), this.signedCommitment);
	}

	public void setOpening() {
		this.r_and_offset = new byte[][] { this.r, this.offsetInBytes };
	}

	public void setOpening(byte[] r, byte[] offset) {
		this.r_and_offset = new byte[][] { r, offset };
	}

	public byte[][] getOpening() {
		return this.r_and_offset;
	}

	public void setSignedOpening() {
		this.signedR = MHDESignature.signWithDSA(this.r, this.signSK);
		this.signedOffset = MHDESignature.signWithDSA(this.offsetInBytes, this.signSK);
		this.r_and_offset_signed = new byte[][] { this.signedR, this.signedOffset };
	}

	public void setSignedOpening(byte[] signedR, byte[] signedOffset) {
		this.r_and_offset_signed = new byte[][] { signedR, signedOffset };
	}

	public byte[][] getSignedOpening() {
		return this.r_and_offset_signed;
	}

	public void sendOpeningAndSignature() {
		VerifierProxy vProxy=VerifierProxy.getInstance();
		vProxy.updateOpenings(this.getNodeName(), this.r_and_offset);
		vProxy.updateSignedOpenings(this.getNodeName(), this.r_and_offset_signed);
	}

	public void applyDelay(int delay) {
		try {
			Thread.sleep(0, delay);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

}
