/**
 * MHDECommitment.java - A class to implement Pedersons' binding-and-hiding-commitment scheme.
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.crypto;

import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

public class MHDECommitment {
	public static BigInteger p;// a large prime
	public static BigInteger q;// a large prime such that q|(p-1)
	public static BigInteger g;// a generator of the order-q
	public static BigInteger h;//g^a mod p

	/*
	 * This static block initializes the p,q,g and h public parameters as
	 * defined in Pedersons' commitment scheme.
	 */

	static {
		Properties prop = new Properties();
		InputStream inputStream;
		try {
			inputStream = new FileInputStream("inputs\\pqgTriple");
			prop.load(inputStream);
			p = new BigInteger(prop.getProperty("p"));
			q = new BigInteger(prop.getProperty("q"));
			g = new BigInteger(prop.getProperty("g"));
			BigInteger a = new BigInteger(159, new Random());
			h = g.modPow(a, p);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * This is the commit-phase of the Pedersons' scheme. Commit a given message
	 * using Pedersons' scheme. As output it returns the r value chosen by the
	 * committer and the resulting commitment value.
	 * 
	 * @param message
	 *            the message that should be committed
	 * @return the commitment and the r values which are later used in opening
	 *         phase
	 */
	public static byte[][] commitWithPederson(byte[] message) {
		BigInteger r = new BigInteger(159, new Random());
		BigInteger commitment = calculateCommitment(new BigInteger(message), r);

		return new byte[][] { r.toByteArray(), commitment.toByteArray() };
	}

	/**
	 * This is the opening-phase of the Pedersons' scheme. The opening value
	 * consists of pair {r,message}. When this pair is given, this method checks
	 * whether the opening value matches the commitment.
	 * 
	 * @param r
	 *            resulting r value obtained in the commit-phase
	 * @param message
	 *            original message committed
	 * @param commitment
	 *            commitment value obtained int he commit-phase
	 * @return true if opening matches commitment, or false otherwise
	 */

	public static boolean verifyWithPederson(byte[] r, byte[] message, byte[] commitment) {
		BigInteger c = calculateCommitment(new BigInteger(message), new BigInteger(r));

		return Arrays.equals(c.toByteArray(), commitment);
	}

	/* Calculate and returns the commitment given r and message */
	private static BigInteger calculateCommitment(BigInteger m, BigInteger r) {
		// (A*B) mod C=(A mod C*B mod C) mod C
		BigInteger g_Pow_m = g.modPow(m, p);
		BigInteger h_pow_r = h.modPow(r, p);
		BigInteger c = (g_Pow_m.multiply(h_pow_r)).mod(p);

		return c;
	}

}
