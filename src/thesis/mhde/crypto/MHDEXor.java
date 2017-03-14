/**
 * MHDEXor.java - A simple class to perform bit level operations
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.crypto;

public class MHDEXor {

	/**
	 * Given a bit sequence denoted as a String, this method returns the
	 * bit-String in a given index. The bit sequence is zero-indexed
	 * 
	 * @param bitSequence
	 *            the bit sequence denoted as a String eg:- "1011101"
	 * @param index
	 *            index of the bit
	 * @return the String bit at given index
	 */
	public static String bitAt(String bitSequence, int index) {
		return bitSequence.substring(index, index + 1);
	}

	/**
	 * Perform the xor operation on given two String bits and return the
	 * resulting String bit. eg:- "1" xor "0"="1"
	 * 
	 * @param bit_1
	 *            String bit 1
	 * @param bit_2
	 *            String bit 2
	 * @return resulting String bit
	 */
	public static String xorBits(String bit_1, String bit_2) {
		if (bit_1.equals(bit_2))
			return "0";
		else
			return "1";
	}

	/**
	 * Concatenates byte array2 to the end of byte array 1 and return the result
	 * 
	 * @param array1
	 *            byte array 1
	 * @param array2
	 *            byte array 2
	 * @return resulting concatenated byte array
	 */

	public static byte[] concat(byte[] array1, byte[] array2) {
		byte[] concatenation = new byte[array1.length + array2.length];
		for (int i = 0; i < concatenation.length; i++) {
			concatenation[i] = i < array1.length ? array1[i] : array2[i - array1.length];
		}

		return concatenation;
	}

}
