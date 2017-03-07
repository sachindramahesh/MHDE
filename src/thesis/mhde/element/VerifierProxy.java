package thesis.mhde.element;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

public class VerifierProxy {

	private static VerifierProxy vProxy = new VerifierProxy();

	private int numOfPaths;
	private double tDelta;
	// HashMap<String, long[]> times = VerifierProxy.getTiming();
	private LinkedList<String> prunedPaths = new LinkedList<String>();
	private final long C = 299792458L;// speed of light

	private static HashMap<String, byte[]> commits = new HashMap<String, byte[]>();
	private static HashMap<String, byte[]> signedCommits = new HashMap<String, byte[]>();

	public void updateCommits(String node, byte[] commit) {
		commits.put(node, commit);
	}

	public HashMap<String, byte[]> getCommits() {
		return commits;
	}

	public void updateSignedCommits(String node, byte[] signedCommit) {
		signedCommits.put(node, signedCommit);
	}

	public HashMap<String, byte[]> getSignedCommits() {
		return signedCommits;
	}

	private static HashMap<String, byte[][]> openings = new HashMap<String, byte[][]>();// r,m
	private static HashMap<String, byte[][]> signedOpenings = new HashMap<String, byte[][]>();// signed
																								// r,m

	public void updateOpenings(String node, byte[][] opening) {
		openings.put(node, opening);
	}

	public HashMap<String, byte[][]> getOpenings() {
		return openings;
	}

	public void updateSignedOpenings(String node, byte[][] signedOpening) {
		signedOpenings.put(node, signedOpening);
	}

	public HashMap<String, byte[][]> getSignedOpenings() {
		return signedOpenings;
	}

	private static HashMap<String, long[]> timing = new HashMap<String, long[]>();

	public static HashMap<String, long[]> getTiming() {
		return timing;
	}

	public static void setTiming(String path, long[] time) {
		timing.put(path, time);
	}
	
	private static LinkedList<Boolean> auth=new LinkedList<Boolean>();

	public static LinkedList<Boolean> getAuth() {
		return auth;
	}

	public static void updateAuthentication(Boolean bool) {
		auth.add(bool);
	}

	private VerifierProxy() {
	}

	public static VerifierProxy getInstance() {
		return vProxy;
	}

	public void setNumOfPaths(int numOfPaths) {
		this.numOfPaths = numOfPaths;
	}

	public void setTDelta(double tDelta) {
		this.tDelta = tDelta;
	}

	public void decideAuthentication() {		
		if (auth.contains(new Boolean(false))) {
			System.out.println("Prover cannot be authenticated");
		} else {
			System.out.println("Prover is authenticated");
		}

	}

	public void estimateDistance() {
		this.prunePaths();
		long[] averageTimes = this.calculateAverages();
		if (averageTimes.length == 0) {
			System.out.println("All the paths are pruned. None left");
		} else {
			// long min = averageTimes[0];
			//
			// for (int i = 1; i < averageTimes.length; i++) {
			// if (min > averageTimes[i])
			// min = averageTimes[i];
			// }
			// System.out.println("minimum average time " + min + " ns");
			// double minSeconds = min / 1000000000.0;
			// //System.out.println("minimum average time " + minSeconds +
			// " s");
			// double estimatedMinDistance = (minSeconds / 2 ) * C;
			//
			// System.out.printf("Estimated min distance: %f m \n",
			// estimatedMinDistance);

			// Double toBeTruncated=new Double(minSeconds);
			// Double truncatedDouble=new BigDecimal(toBeTruncated).setScale(3,
			// BigDecimal.ROUND_HALF_UP).doubleValue();
			// System.out.println("truncated min time: "+truncatedDouble+" s");
			// double truncatedDistance= (truncatedDouble/2)*C;
			// System.out.printf("Estimated truncated distance: %f m \n
			// ",truncatedDistance
			// );

			this.estimateMinDistance(averageTimes);
			this.estimateMaxDistance(averageTimes);
			this.estimateAvgDistance(averageTimes);
			this.estimateMedianDistance(averageTimes);
			// this.estimateModeDistance(averageTimes);
		}
	}

	private void estimateMinDistance(long[] avgTimes) {

		long min = avgTimes[0];

		for (int i = 1; i < avgTimes.length; i++) {
			if (min > avgTimes[i])
				min = avgTimes[i];
		}
		System.out.print("Minimum=>  Average_time: " + min + " ns, ");
		double minSeconds = min / 1000000000.0;
		// System.out.println("minimum average time " + minSeconds + " s");
		double estimatedMinDistance = (minSeconds / 2) * C;

		System.out.printf(" Estimated_distance: %f m \n", estimatedMinDistance);

	}

	private void estimateMaxDistance(long[] avgTimes) {

		long max = avgTimes[0];

		for (int i = 1; i < avgTimes.length; i++) {
			if (max < avgTimes[i])
				max = avgTimes[i];
		}
		System.out.print("Maximum=> Average_time: " + max + " ns, ");
		double maxSeconds = max / 1000000000.0;
		// System.out.println("minimum average time " + minSeconds + " s");
		double estimatedMaxDistance = (maxSeconds / 2) * C;

		System.out.printf("Estimated_distance: %f m \n", estimatedMaxDistance);

	}

	private void estimateAvgDistance(long[] avgTimes) {

		long total = avgTimes[0];

		for (int i = 1; i < avgTimes.length; i++) {
			total = total + avgTimes[i];
		}
		double avgTime = total / avgTimes.length;
		System.out.print("Average=> Average_time: " + avgTime + " ns,");
		double avgSeconds = avgTime / 1000000000.0;
		// System.out.println("minimum average time " + minSeconds + " s");
		double estimatedAvgDistance = (avgSeconds / 2) * C;

		System.out.printf("Estimated_distance: %f m \n", estimatedAvgDistance);

	}

	private void estimateMedianDistance(long[] avgTimes) {

		Arrays.sort(avgTimes);

		int middle = avgTimes.length / 2;
		long median = 0;
		if (avgTimes.length % 2 == 1) {
			median = avgTimes[middle];
		} else {
			median = (avgTimes[middle - 1] + avgTimes[middle]) / 2;
		}

		System.out.print("Median => Average_time " + median + " ns,");
		double medianSeconds = median / 1000000000.0;
		// System.out.println("minimum average time " + minSeconds + " s");
		double estimatedMedianDistance = (medianSeconds / 2) * C;

		System.out.printf("Estimated_distance: %f m \n", estimatedMedianDistance);

	}

	private void estimateModeDistance(long[] avgTimes) {

		int maxCount = 0;
		long modeValue = 0;

		for (int i = 0; i < avgTimes.length; ++i) {
			int count = 0;
			for (int j = 0; j < avgTimes.length; ++j) {
				if (avgTimes[j] == avgTimes[i])
					++count;
			}
			if (count > maxCount) {
				maxCount = count;
				modeValue = avgTimes[i];
			}
		}

		System.out.println("mode average time " + modeValue + " ns");
		double modeSeconds = modeValue / 1000000000.0;
		// System.out.println("minimum average time " + minSeconds + " s");
		double estimatedModeDistance = (modeSeconds / 2) * C;

		System.out.printf("Estimated mode distance: %f m \n", estimatedModeDistance);

	}

	private void prunePaths() {

		int pathsRemoved = 0;

		for (int i = 1; i <= numOfPaths; i++) {
			long[] t = timing.get("path_" + i);
			// System.out.println("In prune paths");
			// for (int j = 0; j < t.length; j++) {
			// System.out.println(j+": "+t[j]);
			// }
			int lengthJ = (int) t[t.length - 1];// last element has got the
												// length of the path
			boolean removePath = false;
			for (int j = 0; j < t.length - 1; j++) {// tDelta is in nano seconds
				if (t[j] < tDelta * lengthJ || t[j] > 2 * tDelta * lengthJ) {
					removePath = true;
					pathsRemoved++;
					break;
				}
			}
			if (!removePath) {
				this.prunedPaths.add("path_" + i);
			}
		}

		System.out.println(
				"Total paths: " + numOfPaths + " Pruned Paths: " + pathsRemoved + " Paths left: " + prunedPaths.size());
		// System.out.println("paths remaining after pruning: "
		// + prunedPaths.size());
	}

	private long[] calculateAverages() {
		long[] avgTimes = new long[prunedPaths.size()];

		for (int i = 0; i < avgTimes.length; i++) {
			long[] t = timing.get(prunedPaths.get(i));
			long temp = 0;
			for (int j = 0; j < t.length - 1; j++) {
				temp = temp + t[j];
			}
			avgTimes[i] = temp / (t.length - 1);

			System.out.println("Average time " + prunedPaths.get(i) + " " + avgTimes[i] + " ns");
		}

		return avgTimes;

	}

}
