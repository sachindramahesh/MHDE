package mhde.elements;

import java.security.SecureRandom;

public class RandomNumberGenerator extends SecureRandom {

	/**
	 * 
	 */
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

		/*while (number.length() != length) {
			i = instance.next(length);
			number = Integer.toBinaryString(i);
		}*/
		int len=number.length();
		//System.out.println("length ="+len);
		//System.out.println("original number="+number);
		
		if(len<length){
			int diff=length-len;
			//System.out.println("difference="+diff);
			String temp="";
			for (int j = 0; j < diff; j++) {
				temp=temp.concat("0");
			}
			number=temp.concat(number);
			
		}
		

		return number;
	}

	/*public static void main(String[] args) {
		RandomNumberGenerator rng = RandomNumberGenerator.getInstance();
		// System.out.println(rng.nextRandomNumber(1));
		// System.out.println(rng.nextRandomNumber(2));
		// System.out.println(rng.nextRandomNumber(3));
		// System.out.println(rng.nextRandomNumber(4));

		String number = rng.nextRandomNumber(5);
		System.out.println("Number =" + number);
		System.out.println("new length="+number.length());

	}*/

}
