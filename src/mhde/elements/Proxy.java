package mhde.elements;

import java.security.KeyPair;

public class Proxy extends Node implements Runnable {
	
	

	

	public Proxy(String name, Link leftLink, Link rightLink, KeyPair kp, int n) {
		super(name, leftLink, rightLink, kp, n);
	}

	public void run() {
		Link leftLink = this.getLeftLink();
		Link rightLink = this.getRightLink();

		synchronized (rightLink) {
			if (!rightLink.getFlag().equals(this.getName())) {
				try {
					rightLink.wait();
				} catch (InterruptedException e) {
				}
			}
			synchronized (leftLink) {
				this.phaseZero();
				leftLink.setFlag(leftLink.getLeftNode());
				leftLink.notify();
			}
			synchronized (leftLink) {
				if (!leftLink.getFlag().equals(this.getName())) {
					try {
						leftLink.wait();
					} catch (InterruptedException e) {
					}
				}
				this.phaseOne();
				rightLink.setFlag(rightLink.getRightNode());
				rightLink.notify();
			}
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
				synchronized (leftLink) {
					this.phaseTwo_first();
					leftLink.setFlag(leftLink.getLeftNode());
					leftLink.notify();
				}
				synchronized (leftLink) {
					if (!leftLink.getFlag().equals(this.getName())) {
						try {
							leftLink.wait();
						} catch (InterruptedException e) {
						}
					}
					this.phaseTwo_second(i);
					rightLink.setFlag(rightLink.getRightNode());
					rightLink.notify();
				}
			}
		}
		
		
		synchronized (rightLink) {
			if (!rightLink.getFlag().equals(this.getName())) {
				try {
					rightLink.wait();
				} catch (InterruptedException e) {
				}
			}
			synchronized (leftLink) {
				leftLink.setFlag(leftLink.getLeftNode());
				leftLink.notify();
			}
			synchronized (leftLink) {
				if (!leftLink.getFlag().equals(this.getName())) {
					try {
						leftLink.wait();
					} catch (InterruptedException e) {
					}
				}
				this.phaseThree();
				rightLink.setFlag(rightLink.getRightNode());
				rightLink.notify();
			}
		}

		

	}

	public void phaseZero() {
		
		Link rightLink = this.getRightLink();
		Link leftLink = this.getLeftLink();
		
		byte[][] data=rightLink.getPhase0_data();
		byte[] path=data[0];
		byte[] sign=data[1];		
		
		boolean verifies=this.verifyData(path, sign, TrustedThirdParty.getVerifierPublicKey_Sign());
		System.out.println(this.getName() + " " + verifies);
		leftLink.setPhase0_data(path, sign);

	}

	public void phaseOne() {


		this.setN_bitString(this.getN());
		this.setOffset();
		this.doCommit();
		this.signCommit();
		this.sendCommitAndSignature();
		
		System.out.println(this.getName()+"'s n-bit offset string "+this.getN_bitString());


	}

	public void phaseTwo_first() {
//		int temp = this.getRightLink().getData_0();
//		this.getLeftLink().setData_0(temp);		
		String challenge=this.getRightLink().getChallenge();
		this.getLeftLink().setChallenge(challenge);
		try {
			Thread.sleep(1000);
			System.out.println("delayed 1000ms by "+this.getName());

		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public void phaseTwo_second(int round) {

		
		String challenge=this.getLeftLink().getResponse();
		String offsetBit=this.bitAt(this.getN_bitString(), round);
		String response=this.xorBits(challenge, offsetBit);
		this.getRightLink().setResponse(response);
		try {
			Thread.sleep(1000);
			System.out.println("delayed 1000ms by "+this.getName());

		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public void phaseThree(){
		this.setOpening();
		this.setSignedOpening();
		this.sendOpeningAndSignature();
		
	}

}
