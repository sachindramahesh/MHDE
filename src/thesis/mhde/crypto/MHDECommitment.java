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

	public static byte[][] commitWithPederson(byte[] message) {	
		BigInteger r=new BigInteger(159, new Random());
		BigInteger commitment=calculateCommitment(new BigInteger(message), r);

		return new byte[][]{r.toByteArray(),commitment.toByteArray()};		
	}
	
	public static boolean verifyWithPederson(byte[] r, byte[] message, byte[] commitment){
		BigInteger c=calculateCommitment(new BigInteger(message), new BigInteger(r));

		return Arrays.equals(c.toByteArray(), commitment);		
	}
	
	private static BigInteger calculateCommitment(BigInteger m,BigInteger r){
		//(A*B) mod C=(A mod C*B mod C) mod C
		BigInteger g_Pow_m= g.modPow(m, p);
		BigInteger h_pow_r=h.modPow(r, p);
		BigInteger c=(g_Pow_m.multiply(h_pow_r)).mod(p);
		
		return c;		
	}

}
