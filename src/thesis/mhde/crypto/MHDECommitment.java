package thesis.mhde.crypto;

import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

public class MHDECommitment {
	public static BigInteger p;
	public static BigInteger q;
	public static BigInteger g;
	public static BigInteger h;
	
	static{
		Properties prop=new Properties();
		InputStream inputStream;		
		try{
			inputStream=new FileInputStream("PQG\\pqgTriple");
			prop.load(inputStream);
			p=new BigInteger(prop.getProperty("p"));
			q=new BigInteger(prop.getProperty("q"));
			g=new BigInteger(prop.getProperty("g"));
			BigInteger a = new BigInteger(159, new Random());
			h=g.modPow(a, p);			
		}
		catch(Exception e){
			e.printStackTrace();			
		}		
	}
	
	public static BigInteger[] commitWithPederson(BigInteger message) {	
		BigInteger r=new BigInteger(159, new Random());
		BigInteger commitment=calculateCommitment(message, r);
		
		return new BigInteger[]{r,commitment};		
	}
	

	
	public static boolean verifyWithPederson(BigInteger r, BigInteger message, BigInteger commitment){
		BigInteger c=calculateCommitment(message, r);
		
		return c.equals(commitment);		
	}
	
	private static BigInteger calculateCommitment(BigInteger m,BigInteger r){
		//(A*B) mod C=(A mod C*B mod C) mod C
		BigInteger g_Pow_m= g.modPow(m, p);
		BigInteger h_pow_r=h.modPow(r, p);
		BigInteger c=(g_Pow_m.multiply(h_pow_r)).mod(p);
		
		return c;		
	}
	//
	// public static void main(String[] args) {
	// String offset=MHDERandomNumberGenerator.getNextRandomNumber(16);
	// System.out.println("offset :"+offset);
	// BigInteger offsetBI=new BigInteger(offset, 2);
	// System.out.println("offset as a BIG Integer: "+offsetBI);
	//
	// BigInteger[] r_c=commitWithPederson(offsetBI);
	// System.out.println("Does open match commitment:
	// "+verifyWithPederson(r_c[0], offsetBI, r_c[1]));
	//
	//
	// System.out.println("\n\n\ncheck with byte[] arguments");
	// byte[][] r_and_c=commitWithPederson(offset.getBytes());
	// System.out.println("Does open match commitment with byte[]:
	// "+verifyWithPederson(r_and_c[0], offset.getBytes(), r_and_c[1]));
	// }
	//
	
	public static byte[][] commitWithPederson(byte[] message) {	
		BigInteger r=new BigInteger(159, new Random());
		BigInteger commitment=calculateCommitment(new BigInteger(message), r);
		
		// System.out.println("message to byte array");
		// for (byte b : message) {
		// System.out.print(b+" ");
		// }
		//
		//
		// System.out.println("\nr to byte array");
		// for (byte b : r.toByteArray()) {
		// System.out.print(b+" ");
		// }
		//
		// System.out.println("\ncommitment to byte array");
		// for (byte b : commitment.toByteArray()) {
		// System.out.print(b+" ");
		// }
		//
		return new byte[][]{r.toByteArray(),commitment.toByteArray()};		
	}
	
	public static boolean verifyWithPederson(byte[] r, byte[] message, byte[] commitment){
		BigInteger c=calculateCommitment(new BigInteger(message), new BigInteger(r));
		
		
		// System.out.println("\nmessage to byte array");
		// for (byte b : message) {
		// System.out.print(b+" ");
		// }
		//
		//
		// System.out.println("\nr to byte array");
		// for (byte b : r) {
		// System.out.print(b+" ");
		// }
		//
		// System.out.println("\ncommitment to byte array");
		// for (byte b : commitment) {
		// System.out.print(b+" ");
		// }
		//
		// System.out.println("\nc to byte array");
		// for (byte b : c.toByteArray()) {
		// System.out.print(b+" ");
		// }
		// System.out.println();
		
		return Arrays.equals(c.toByteArray(), commitment);		
	}

}
