/**
 * VerifierProxy.java - A singleton class that act as the ultimate verifier. This collects the values obtained by each
 * Verifier created for each path and does the final calculations
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.element;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

public class VerifierProxy {

	private int numOfPaths;// number of paths
	private double tDelta;// tDelta value corresponding
	private LinkedList<String> prunedPaths = new LinkedList<String>();
	private final long C = 299792458L;// speed of light

	// authentication for each path
	private static LinkedList<Boolean> auth = new LinkedList<Boolean>();
	// time taken by each path for challenge-respose rounds
	private static HashMap<String, long[]> timing = new HashMap<String, long[]>();
	// stores the commit values sent by users
	private static HashMap<String, byte[]> commits = new HashMap<String, byte[]>();
	// stores the signatures of commits sent by the users
	private static HashMap<String, byte[]> signedCommits = new HashMap<String, byte[]>();
	// stores opening values{r,m} sent by the user
	private static HashMap<String, byte[][]> openings = new HashMap<String, byte[][]>();
	// stores the signed opening values sent by the users
	private static HashMap<String, byte[][]> signedOpenings = new HashMap<String, byte[][]>();

	// Singleton pattern for VerifierProxy
	private VerifierProxy() {
	}

	private static VerifierProxy vProxy = new VerifierProxy();

	public static VerifierProxy getInstance() {
		return vProxy;
	}

	/**
	 * Store a commit value sent by a user
	 * 
	 * @param node
	 *            user name
	 * @param commit
	 *            commit value
	 */
	public void updateCommits(String node, byte[] commit) {
		commits.put(node, commit);
	}

	/**
	 * Returns all the stored commit values
	 * 
	 * @return commits
	 */
	public HashMap<String, byte[]> getCommits() {
		return commits;
	}

	/**
	 * Stores the signature of a commit value sent by a user
	 * 
	 * @param node
	 *            user name
	 * @param signedCommit
	 *            signature of a commit value
	 */
	public void updateSignedCommits(String node, byte[] signedCommit) {
		signedCommits.put(node, signedCommit);
	}

	/**
	 * Returns all the signatures of commit values
	 * 
	 * @return signatures
	 */
	public HashMap<String, byte[]> getSignedCommits() {
		return signedCommits;
	}

	/**
	 * Store the opening value sent by a user
	 * 
	 * @param node
	 *            user name
	 * @param opening
	 *            opening value
	 */
	public void updateOpenings(String node, byte[][] opening) {
		openings.put(node, opening);
	}

	/**
	 * Return all the opening values
	 * 
	 * @return
	 */
	public HashMap<String, byte[][]> getOpenings() {
		return openings;
	}

	/**
	 * Store the signature of a opening value sent by a user
	 * 
	 * @param node
	 *            user name
	 * @param signedOpening
	 *            signature of a opening value
	 */
	public void updateSignedOpenings(String node, byte[][] signedOpening) {
		signedOpenings.put(node, signedOpening);
	}

	/**
	 * Returns all the signed opening values
	 * 
	 * @return signed opening values
	 */
	public HashMap<String, byte[][]> getSignedOpenings() {
		return signedOpenings;
	}

	/**
	 * Returns all the timing values
	 * 
	 * @return timing values
	 */
	public static HashMap<String, long[]> getTiming() {
		return timing;
	}

	/**
	 * Store a challenge-response timing value of a given path
	 * 
	 * @param path
	 *            name of the path
	 * @param time
	 *            time taken to complete the challenge-response rounds
	 */
	public static void setTiming(String path, long[] time) {
		timing.put(path, time);
	}

	/**
	 * Returns the authentication values of each path
	 * 
	 * @return
	 */
	public static LinkedList<Boolean> getAuth() {
		return auth;
	}

	/**
	 * Update the authentication list
	 * 
	 * @param bool
	 *            a true or false value
	 */
	public static void updateAuthentication(Boolean bool) {
		auth.add(bool);
	}

	/**
	 * Set the number of paths
	 * 
	 * @param numOfPaths
	 *            number of paths
	 */
	public void setNumOfPaths(int numOfPaths) {
		this.numOfPaths = numOfPaths;
	}

	/**
	 * Set the t-delta value as specified
	 * 
	 * @param tDelta
	 *            t-delta value
	 */
	public void setTDelta(double tDelta) {
		this.tDelta = tDelta;
	}

	/**
	 * Decide whether the prover can be authenticated or not
	 */
	public void decideAuthentication() {
		if (auth.contains(new Boolean(false))) {
			System.out.println("Prover cannot be authenticated");
		} else {
			System.out.println("Prover is authenticated");
		}
	}

	/**
	 * Estimate the distance between the Prover and the Verifier
	 */
	public void estimateDistance() {
		this.prunePaths();
		long[] averageTimes = this.calculateAverages();
		if (averageTimes.length == 0) {
			System.out.println("All the paths are pruned. None left");
		} else {

			this.estimateMinDistance(averageTimes);
			this.estimateMaxDistance(averageTimes);
			this.estimateAvgDistance(averageTimes);
			this.estimateMedianDistance(averageTimes);
		}
	}

	/*
	 * Calculate the median distance between the Prover and the Verifier
	 */
	private void estimateMinDistance(long[] avgTimes) {

		long min = avgTimes[0];
		for (int i = 1; i < avgTimes.length; i++) {
			if (min > avgTimes[i])
				min = avgTimes[i];
		}

		System.out.print("Minimum=>  Average_time: " + min + " ns, ");
		double minSeconds = min / 1000000000.0;
		double estimatedMinDistance = (minSeconds / 2) * C;
		System.out.printf(" Estimated_distance: %f m \n", estimatedMinDistance);
	}

	/*
	 * Calculate the maximum distance between the Prover and the Verifier
	 */
	private void estimateMaxDistance(long[] avgTimes) {

		long max = avgTimes[0];
		for (int i = 1; i < avgTimes.length; i++) {
			if (max < avgTimes[i])
				max = avgTimes[i];
		}

		System.out.print("Maximum=> Average_time: " + max + " ns, ");
		double maxSeconds = max / 1000000000.0;
		double estimatedMaxDistance = (maxSeconds / 2) * C;
		System.out.printf("Estimated_distance: %f m \n", estimatedMaxDistance);
	}

	/*
	 * Calculate the average distance between the Prover and the Verifier
	 */
	private void estimateAvgDistance(long[] avgTimes) {

		long total = avgTimes[0];
		for (int i = 1; i < avgTimes.length; i++) {
			total = total + avgTimes[i];
		}

		double avgTime = total / avgTimes.length;
		System.out.print("Average=> Average_time: " + avgTime + " ns,");
		double avgSeconds = avgTime / 1000000000.0;
		double estimatedAvgDistance = (avgSeconds / 2) * C;

		System.out.printf("Estimated_distance: %f m \n", estimatedAvgDistance);
	}

	/*
	 * Calculate the median distance between the Prover and the Verifier
	 */
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
		double estimatedMedianDistance = (medianSeconds / 2) * C;
		System.out.printf("Estimated_distance: %f m \n", estimatedMedianDistance);
	}

	/*
	 * Prune the paths that do not meet the criteria
	 */
	private void prunePaths() {

		int pathsRemoved = 0;

		for (int i = 1; i <= numOfPaths; i++) {
			long[] t = timing.get("path_" + i);
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

		System.out.println("\n\nTotal paths: " + numOfPaths + " Pruned Paths: " + pathsRemoved + " Paths left: "
				+ prunedPaths.size());

	}

	/*
	 * Calculate the average time for each pruned path
	 */
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
