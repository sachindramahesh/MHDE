package thesis.mhde.element;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.LinkedList;

import thesis.mhde.crypto.MHDERandomNumberGenerator;

public class TrustedThirdParty {

	private static TrustedThirdParty ttp = new TrustedThirdParty();
	private static HashMap<String, KeyPair> keysSet=new HashMap<String, KeyPair>();//keys for signing
	private static HashMap<String, byte[]> commits=new HashMap<String, byte[]>();
	private static HashMap<String, byte[]> signedCommits=new HashMap<String, byte[]>();
	private static HashMap<String, byte[][]> openings=new HashMap<String, byte[][]>();//r,m
	private static HashMap<String, byte[][]> signedOpenings=new HashMap<String, byte[][]>();//signed r,m
	private static HashMap<String, long[]> timing=new HashMap<String, long[]>();
	private static LinkedList<Boolean> auth=new LinkedList<Boolean>();
	private static String secretK;

	private TrustedThirdParty() {
		
	}

	public static TrustedThirdParty getInstance() {
		return ttp;
	}
	
	public static PublicKey getVerifierPublicKey_Sign(){
		return keysSet.get("V").getPublic();
	}
	
	public static PublicKey getVerifierPublicKey_Encrypt(){
		return keysSet.get("VC").getPublic();
	}
	
	public PublicKey getUserPublicKey_Sign(String username){
		return keysSet.get(username).getPublic();
	}

	
	public HashMap<String, KeyPair> registerUsers(int numOfPaths,HashMap<String, String> pathList,int n) {
		this.setSecretK(n);
		
		int keysize=4096;
		
		if(n==64)
			keysize=1024;
		else if(n==128)
			keysize=2048;
		else if(n==256)
			keysize=4096;

		try {
			KeyPairGenerator keyGen = KeyPairGenerator
					.getInstance("DSA", "SUN");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(2048, random);
			
			KeyPair verifierPair=keyGen.generateKeyPair();
			keysSet.put("V", verifierPair);
			
			KeyPair proverPair=keyGen.generateKeyPair();
			keysSet.put("U", proverPair);
			
			for (int i = 1; i <= numOfPaths; i++) {
				String[] users=pathList.get("path_"+i).split("\\s*,\\s*");
				for (int j = 1; j < users.length-1; j++) {
					KeyPair pair=keyGen.generateKeyPair();
					keysSet.put(users[j].trim(), pair);
					
				}				
			}
			
			KeyPairGenerator cipherKeyGen=KeyPairGenerator.getInstance("RSA");
			//int
			cipherKeyGen.initialize(keysize, random);	//RSA key size-2048 bits		
			KeyPair cipherPair=cipherKeyGen.generateKeyPair();
			keysSet.put("VC", cipherPair);// verifier cipher keys
			
			
		} 
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
		catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		
		return keysSet;

	}
	
	public void updateCommits(String node, byte[] commit){
		commits.put(node, commit);
	}
	
	public  HashMap<String, byte[]> getCommits() {
		return commits;
	}
	
	public void updateSignedCommits(String node, byte[] signedCommit){
		signedCommits.put(node, signedCommit);
	}	

	public  HashMap<String, byte[]> getSignedCommits() {
		return signedCommits;
	}
	
	public void updateOpenings(String node, byte[][] opening){
		openings.put(node, opening);
	}
	
	public HashMap<String, byte[][]> getOpenings() {
		return openings;
	}
	
	public void updateSignedOpenings(String node, byte[][] signedOpening){
		signedOpenings.put(node, signedOpening);
	}	

	public HashMap<String, byte[][]> getSignedOpenings() {
		return signedOpenings;
	}
	
	private void setSecretK(int n) {
		
		secretK=MHDERandomNumberGenerator.getNextRandomNumber(n);
	}
	
	public String getSecretK(){
		return secretK;		
	}
	
	public PrivateKey getVerifierPrivateKey(){
		return keysSet.get("VC").getPrivate();
	}

	public static HashMap<String, long[]> getTiming() {
		return timing;
	}

	public static void setTiming(String path, long[] time) {
		timing.put(path, time);
	}
	
	public static LinkedList<Boolean> getAuth() {
		//auth.add(new Boolean(false));
		return auth;
	}
	public static void  updateAuthentication(Boolean bool) {
		auth.add(bool);
	}
	


}
