package mhde.elements;

import java.security.SecureRandom;

public class RandomNumberGenerator extends SecureRandom {

	private static final long serialVersionUID = 1L;

	private static RandomNumberGenerator instance = new RandomNumberGenerator();

	private RandomNumberGenerator() {
	}

	public static RandomNumberGenerator getInstance() {
		return instance;
	}

	public String nextRandomNumber(int length) {
		int i = instance.next(length);
		String number = Integer.toBinaryString(i);

		/*
		 * while (number.length() != length) { i = instance.next(length); number
		 * = Integer.toBinaryString(i); }
		 */

		int len = number.length();

		if (len < length) {
			int diff = length - len;
			String temp = "";
			for (int j = 0; j < diff; j++) {
				temp = temp.concat("0");
			}
			number = temp.concat(number);
		}

		return number;
	}

}
