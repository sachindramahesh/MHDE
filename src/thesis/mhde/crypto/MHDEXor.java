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

}
