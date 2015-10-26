package mhde.elements;

import java.util.HashMap;
import java.util.LinkedList;

public class VerifierProxy {

	private int numOfPaths;
	private long tDelta;
	HashMap<String, long[]> times = TrustedThirdParty.getTiming();
	private LinkedList<String> prunedPaths = new LinkedList<String>();

	private final long C = 299792458L;

	public VerifierProxy(int numOfPaths, long tDelta) {
		this.numOfPaths = numOfPaths;
		this.tDelta = tDelta;
	}

	public void estimateDistance() {
		this.prunePaths();
		long[] averageTimes = this.calculateAverages();
		if (averageTimes.length == 0) {
			System.out.println("All the paths are pruned. None left");
		} else {
			long min = averageTimes[0];

			for (int i = 1; i < averageTimes.length; i++) {
				if (min > averageTimes[i])
					min = averageTimes[i];
			}
			System.out.println("minimum average time " + min + "ns");
			System.out.println("minimum average time " + (min / 1000000000)
					+ "s");
			long estimatedDistance = (min / 1000000000) * C;

			System.out.println("Estimated distance " + estimatedDistance + "m");
		}
	}

	private void prunePaths() {
		
		for (int i = 1; i <= numOfPaths; i++) {
			long[] t = times.get("path_" + i);
			int lengthJ = (int) t[t.length - 1];// last element has got the
												// length of the path			
			boolean removePath = false;			
			for (int j = 0; j < t.length - 1; j++) {
				if (t[j] < tDelta * lengthJ || t[j] > 2 * tDelta * lengthJ) {
					removePath = true;
					break;
				}
			}
			if (!removePath) {
				this.prunedPaths.add("path_" + i);
			}
		}

		System.out.println("pruned paths: " + prunedPaths.size());
	}

	private long[] calculateAverages() {
		long[] avgTimes = new long[prunedPaths.size()];

		for (int i = 0; i < avgTimes.length; i++) {
			long[] t = times.get(prunedPaths.get(i));
			long temp = 0;
			for (int j = 0; j < t.length - 1; j++) {
				temp = temp + t[j];
			}
			avgTimes[i] = temp / (t.length - 1);

			System.out.println("Average time " + prunedPaths.get(i) + " "
					+ avgTimes[i] + "ns");
		}

		return avgTimes;

	}

}
