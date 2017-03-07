package thesis.mhde.crypto;

import java.security.SecureRandom;

public class MHDERandomNumberGenerator extends SecureRandom {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public static String getARandomBit() {
		MHDERandomNumberGenerator rng = new MHDERandomNumberGenerator();
		return rng.getBit();
	}

	private String getBit() {
		return Integer.toBinaryString(next(1));
	}

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
