package mhde.elements;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



public abstract class Node implements Runnable {

	private String name;

	private Link leftLink;
	private Link rightLink;

	private PublicKey spk;//keys for signing
	private PrivateKey ssk;
	
	private int n;

	private String n_bitString;
	private byte[] offset;
	private byte[] commit;
	private byte[] signedCommit;
	
	private byte[] opening;
	private byte[] signedOpening;

	public Node() {
		this.leftLink = null;
		this.rightLink = null;
	}

	public Node(String name, Link leftLink, Link rightLink, KeyPair kp, int n) {
		this.name = name;
		this.leftLink = leftLink;
		this.rightLink = rightLink;
		this.spk = kp.getPublic();
		this.ssk = kp.getPrivate();
		this.n= n;
	}

	public Link getLeftLink() {
		return leftLink;
	}

	public Link getRightLink() {
		return rightLink;
	}

	public PublicKey getPublicKey() {
		return spk;
	}

	public byte[] signData(byte[] data) {
		byte[] realSig = null;
		try {
			Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
			dsa.initSign(ssk);
			dsa.update(data);
			realSig = dsa.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		return realSig;
	}

	public boolean verifyData(byte[] data, byte[] signature, PublicKey pub) {

		boolean verifies = false;

		try {
			Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
			dsa.initVerify(pub);
			dsa.update(data);
			verifies = dsa.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		return verifies;

	}
	
	public byte[] encryptData(byte[] data, PublicKey pub){
		
		
		byte[] ciphertext=null;
		
		
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pub);
			ciphertext=cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return ciphertext;
	}
	
	
	public byte[] decryptData(byte[] data,PrivateKey priv){
		byte[] plaintext=null;
		
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, priv);
			plaintext=cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return plaintext;
		
	}

	//public abstract void phaseZero();

	//public abstract void phaseOne();

	//public abstract void phaseTwo();

	//public abstract void phaseThree();

	public String getName() {
		return name;
	}

	

	public String getN_bitString() {
		return n_bitString;
	}

	public void generate_n_bitString(int n) {
		RandomNumberGenerator rng=RandomNumberGenerator.getInstance();
		this.n_bitString=rng.nextRandomNumber(n);
	}
	
	public void setOffset(){
		this.offset=this.n_bitString.getBytes();
	}
	
	public byte[] getOffset(){
		return this.offset;
	}
	
	public void doCommit(){
		try {			
			MessageDigest sha=MessageDigest.getInstance("SHA-1");
			sha.update(offset);
			this.commit=sha.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public byte[] getCommitment(){
		return this.commit;
	}
	
	public void signCommit(){
		this.signedCommit=this.signData(this.commit);
	}
	
	public byte[] getSignedCommit(){
		return this.signedCommit;
	}
	
	public void sendCommitAndSignature(){
		TrustedThirdParty ttp=TrustedThirdParty.getInstance();
		ttp.updateCommits(this.name, this.commit);
		ttp.updateSignedCommits(this.name, this.signedCommit);
		
	}

	public int getN() {
		return n;
	}
	
	public String bitAt(String bitSequence, int index){
		return bitSequence.substring(index,index+1);
	}
	
	public String xorBits(String bit_1, String bit_2){
		if(bit_1.equals(bit_2))
			return "0";
		else
			return "1";
	}

	public byte[] getOpening() {
		return opening;
	}

	public void setOpening() {
		this.opening = this.offset;
	}
	
	public void setOpening(byte[] open){
		this.opening=open;
	}

	public byte[] getSignedOpening() {
		return signedOpening;
	}

	public void setSignedOpening() {
		this.signedOpening = this.signData(this.opening);
	}
	
	public void setSignedOpening(byte[] signOpen){
		this.signedOpening=signOpen;
	}
	
	
	public void sendOpeningAndSignature(){
		TrustedThirdParty ttp=TrustedThirdParty.getInstance();
		ttp.updateOpenings(this.name, this.opening);
		ttp.updateSignedOpenings(this.name, this.signedOpening);		
	}
	

	
}
