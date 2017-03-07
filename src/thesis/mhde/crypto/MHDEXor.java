package thesis.mhde.crypto;

public class MHDEXor {
	public static String bitAt(String bitSequence, int index) {
		return bitSequence.substring(index, index + 1);
	}

	public static String xorBits(String bit_1, String bit_2) {
		if (bit_1.equals(bit_2))
			return "0";
		else
			return "1";
	}

	
	public static byte[] concat(byte[] array1,byte[] array2){
		byte[] concatenation = new byte[array1.length + array2.length];
		for (int i = 0; i < concatenation.length; i++) {
			concatenation[i] = i < array1.length ? array1[i] :  array2[i - array1.length];
		}
		
		return concatenation;		
	}
	// public static void main(String[] args) {
	// String bitSequence = "1101001";
	// System.out.println("bit sequence: " + bitSequence);
	// System.out.println("bit at 0: " + bitAt(bitSequence, 0));// ->1
	// System.out.println("bit at 1: " + bitAt(bitSequence, 1));// ->1
	// System.out.println("bit at 2: " + bitAt(bitSequence, 2));// ->0
	// System.out.println("bit at 3: " + bitAt(bitSequence, 3));// ->1
	// System.out.println("bit at 4: " + bitAt(bitSequence, 4));// ->0
	// System.out.println("bit at 5: " + bitAt(bitSequence, 5));// ->0
	// System.out.println("bit at 6: " + bitAt(bitSequence, 6));// ->1
	//
	// System.out.println("\n\n");
	// System.out.println("0 xor 0: " + xorBits("0", "0"));// ->0
	// // System.out.println("0
	// // xor 1:
	// // "+xorBits("0",
	// // "1"));//->1
	// System.out.println("1 xor 0: " + xorBits("1", "0"));// ->1
	// System.out.println("1 xor 1: " + xorBits("1", "1"));// ->0
	//
	// }

}
