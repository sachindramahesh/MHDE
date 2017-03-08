/**
 * MHDERandomNumberGenerator.java - A class to generate random Strings of given length 
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.crypto;

import java.security.SecureRandom;

public class MHDERandomNumberGenerator extends SecureRandom {

	private static final long serialVersionUID = 1L;

	/**
	 * Generate a random String of length one. The result is either "0" or "1".
	 * 
	 * @return String "0" or String "1"
	 */

	public static String getARandomBit() {
		MHDERandomNumberGenerator rng = new MHDERandomNumberGenerator();
		return rng.getBit();
	}

	/*
	 * helper method to generate a random 1-bit string. Cannot use next(int)
	 * method inherited from SecureRandom class since it is a instance method.
	 */
	private String getBit() {
		return Integer.toBinaryString(next(1));
	}

	/**
	 * Generate a random String of given length which is usually multiple of 16
	 * 
	 * @param numBits
	 *            length of the random String ot be generated
	 * @return a random String of given length
	 */

	public static String getNextRandomNumber(int numBits) {
		MHDERandomNumberGenerator rng = new MHDERandomNumberGenerator();

		String randomNumber = "";

		if (numBits >= 0 && numBits <= 32) {
			randomNumber = rng.getRandomBlock(numBits);
		} else {
			int factor = numBits / 32;
			for (int i = 0; i < factor; i++) {
				randomNumber = randomNumber.concat(rng.getRandomBlock(32));
			}
		}

		randomNumber = "0".concat(randomNumber.substring(1));

		return randomNumber;
	}

	/*
	 * Helper method to generate random block of strings of given size. This
	 * method was written because next method do not produce a random value
	 * longer than 32-bits
	 */
	private String getRandomBlock(int numBits) {
		String binaryString = Integer.toBinaryString(next(numBits));
		int diff = numBits - binaryString.length();

		if (diff > 0) {
			String temp = "";
			for (int i = 1; i <= diff; i++) {
				if (i % 2 == 1)
					temp = temp.concat("0");
				else
					temp = temp.concat("1");
			}

			binaryString = temp.concat(binaryString);
		}

		return binaryString;
	}

}
