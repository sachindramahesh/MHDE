package mhde.elements;

import java.security.KeyPair;

public class Prover extends Node implements Runnable {
	
	private String[] challenge;
	private String[] response;
	private String[] transcript;
	private String transcriptString;
	
	private String secretKey_K;

	public Prover(String name, Link rightLink, KeyPair kp, int n,String k) {
		super(name, null, rightLink, kp, n);
		this.challenge=new String[n];
		this.response=new String[n];
		this.transcript=new String[2*n];
		this.secretKey_K=k;
		
		System.out.println(this.getName()+"'s n-bit secret "+this.secretKey_K);


	}

	public void run() {
		Link rightLink = this.getRightLink();
		synchronized (rightLink) {
			if (!rightLink.getFlag().equals(this.getName())) {
				try {
					rightLink.wait();
				} catch (InterruptedException e) {
				}
			}
			this.phaseZero();
			this.phaseOne();
			rightLink.setFlag(rightLink.getRightNode());
			rightLink.notify();
		}
		
		int rounds = this.getN();

		for (int i = 0; i < rounds; i++) {
			synchronized (rightLink) {
				if (!rightLink.getFlag().equals(this.getName())) {
					try {
						rightLink.wait();
					} catch (InterruptedException e) {
					}
				}
				this.phaseTwo(i);
				rightLink.setFlag(rightLink.getRightNode());
				
				
				rightLink.notify();
			}
		}
		
		synchronized (rightLink) {
			if (!rightLink.getFlag().equals(this.getName())) {
				try {
					rightLink.wait();
				} catch (InterruptedException e) {
				}
			}
			this.phaseThree();
			rightLink.setFlag(rightLink.getRightNode());
			rightLink.notify();
		}

	}

	public void phaseZero() {
		Link rightLink = this.getRightLink();

		boolean verifies = this.verifyData(rightLink.getPhase0_data(),
				rightLink.getPhase0_sign(),
				TrustedThirdParty.getVerifierPublicKey_Sign());
		System.out.println(this.getName() + " " + verifies);
		
		System.out.println("---------------------PHASE-0 COMPLETED----------------- ");



	}

	public void phaseOne() {
		System.out.println("---------------------PHASE-I STARTED----------------- ");
		this.generate_n_bitString(this.getN());
		this.setOffset();
		this.doCommit();
		this.signCommit();
		this.sendCommitAndSignature();
		
		System.out.println(this.getName()+"'s n-bit offset string "+this.getN_bitString());

	}

	public void phaseTwo(int round) {
		int temp = this.getRightLink().getData_0();
		temp++;
		this.getRightLink().setData_0(temp);
		//System.out.println(this.getName()+" increased to "+ temp);
		
		String offsetBit=this.bitAt(this.getN_bitString(), round);
		String challengeBit=this.getRightLink().getChallenge();//how to use challenge bit
		this.challenge[round]=challengeBit;
		
		String resp="";
		
		if(challengeBit.equals("0")){
			resp=offsetBit;
		}			
		else if(challengeBit.equals("1")){
			String secretKeyBit=this.bitAt(secretKey_K, round);			
			resp=this.xorBits(offsetBit, secretKeyBit);
		}		
		
		this.response[round]=resp;
		this.getRightLink().setResponse(resp);

	}

	public void phaseThree() {
		this.setOpening();
		this.setSignedOpening();
		this.sendOpeningAndSignature();
	}
	
	public void setOpening() {
		
		byte[] tempOpening=this.encryptData(this.getOffset(), TrustedThirdParty.getVerifierPublicKey_Encrypt());
		this.setOpening(tempOpening);
	}
	
	public void setSignedOpening() {
		//this.signedOpening = this.signData(this.opening);
		int rounds=this.getN();
		
		for(int i=0; i<rounds;i++ ){
			transcript[2*i]=challenge[i];
			transcript[(2*i)+1]=response[i];
		}
		
		String temp="";
		
		for (String b : transcript) {
			//System.out.print(b+" ");
			temp=temp.concat(b);
		}
		
		//System.out.println("");
		transcriptString=temp;
		System.out.println("Transcript string at Prover = "+transcriptString);
		
		byte[] openingBytes=this.getOpening();
		byte[] transcriptBytes=transcriptString.getBytes();
		byte[] concatenation=new byte[openingBytes.length+transcriptBytes.length];
		
		for (int i = 0; i < concatenation.length; i++)
		{
		    concatenation[i] = i < openingBytes.length ? openingBytes[i] : transcriptBytes[i - openingBytes.length];
		}
		
		this.setSignedOpening(this.signData(concatenation));
		
		
	}

}