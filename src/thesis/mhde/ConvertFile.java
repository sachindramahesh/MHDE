/**
 * ConvertFile.java - A class to convert a topology file which is based on xyz-coordinates into a topology file based on timing values
 * 
 *@author Mahesh S. Perera
 */

package thesis.mhde;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.Properties;

public class ConvertFile {
	private String num_of_paths;
	private String n_value;
	private String power_radius;
	private HashMap<String, String> pathsCordinates = new HashMap<String, String>();
	private double t_delta;

	/*
	 * Read the topology file given in xyz-coordinates
	 */
	public boolean readTopology(String topologyFile) {

		Properties prop = new Properties();
		InputStream inputStream;

		try {
			inputStream = new FileInputStream(topologyFile);
			prop.load(inputStream);
			this.num_of_paths = prop.getProperty("num_of_paths");
			this.n_value = prop.getProperty("n_value");
			this.power_radius = prop.getProperty("power_radius");

			int n = Integer.parseInt(num_of_paths);

			for (int i = 1; i <= n; i++) {
				pathsCordinates.put("path_" + i, prop.getProperty("path_" + i));
			}

			for (int i = 1; i <= n; i++) {
				System.out.println("path_" + i + "= " + pathsCordinates.get("path_" + i));

			}
			System.out.println("------------------------------------");

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	/*
	 * Create a temporary file with the converted values
	 */
	private void createTempFile(String tempFile) {
		try {
			File f = new File(tempFile);
			OutputStream out = new FileOutputStream(f);
			Properties props = new Properties();
			int n = Integer.parseInt(num_of_paths);

			for (int i = 1; i <= n; i++) {
				String pathCordinates = pathsCordinates.get("path_" + i);
				int numOfUsers = pathCordinates.split("\\s*\\),\\(\\s*").length;
				String path = this.createUserNames(i, numOfUsers);
				String delay = this.convertCordinatesIntoDelays(pathCordinates);
				String mal = this.createMalNames(numOfUsers);

				props.setProperty("path_" + i, path);
				props.setProperty("delay_" + i, delay);
				props.setProperty("mal_" + i, mal);
			}
			props.store(out, null);
			out.flush();
			out.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * Write the converted topology file so that the simulation programme can
	 * read from this
	 */
	public void createTopologyFile(String topologyFile) {
		this.createTempFile("inputs/temp");
		this.t_delta = this.setTDelta();

		Properties prop = new Properties();
		InputStream inputStream;

		try {
			inputStream = new FileInputStream("inputs/temp");
			prop.load(inputStream);

			OutputStream out = new FileOutputStream(topologyFile);
			OutputStreamWriter osw = new OutputStreamWriter(out);

			int numberOfPaths = Integer.parseInt(this.num_of_paths);

			osw.write("num_of_paths=" + numberOfPaths + "\n");
			osw.write("n_value=" + n_value + "\n");
			osw.write("t_delta=" + t_delta + "\n");

			for (int i = 1; i <= numberOfPaths; i++) {
				osw.write("path_" + i + "=" + prop.getProperty("path_" + i) + "\n");
			}
			osw.write("\n");

			for (int i = 1; i <= numberOfPaths; i++) {
				osw.write("delay_" + i + "=" + prop.getProperty("delay_" + i) + "\n");
			}
			osw.write("\n");

			for (int i = 1; i <= numberOfPaths; i++) {
				osw.write("mal_" + i + "=" + prop.getProperty("mal_" + i) + "\n");
			}
			osw.write("\n");

			osw.flush();
			osw.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/*
	 * Convert a path given in coordinates into a path with link propagation
	 * delays
	 */
	private String convertCordinatesIntoDelays(String pathCordinates) {
		pathCordinates = pathCordinates.substring(1, pathCordinates.length() - 1);
		String[] cordinates = pathCordinates.split("\\s*\\),\\(\\s*");
		String pathDelays = "";
		for (int i = 0; i < cordinates.length - 1; i++) {
			if (i == 0) {
				pathDelays = pathDelays + this.calculateDelay(cordinates[i], cordinates[i + 1]);
			} else {
				pathDelays = pathDelays + ", " + this.calculateDelay(cordinates[i], cordinates[i + 1]);
			}
		}
		return pathDelays.trim();
	}

	/*
	 * Calculate the propagation time between two nodes
	 */
	private double calculateDelay(String node1, String node2) {

		final long C = 299792458L;

		String[] xyz_1 = node1.split("\\s*,\\s*");
		double x_1 = Double.parseDouble(xyz_1[0]);
		double y_1 = Double.parseDouble(xyz_1[1]);
		double z_1 = Double.parseDouble(xyz_1[2]);

		String[] xyz_2 = node2.split("\\s*,\\s*");
		double x_2 = Double.parseDouble(xyz_2[0]);
		double y_2 = Double.parseDouble(xyz_2[1]);
		double z_2 = Double.parseDouble(xyz_2[2]);

		double tempDist = Math.pow((x_1 - x_2), 2) + Math.pow((y_1 - y_2), 2) + Math.pow((z_1 - z_2), 2);
		tempDist = Math.round(Math.sqrt(tempDist) * 100.0) / 100.0;
		double delay = Math.round((tempDist / C) * 1000000000 * 100.0) / 100.0;

		return delay;
	}

	/*
	 * Assign names to users. 'U' for Prover, 'V' for Verifier and 'p' with suffix
	 * value for proxies. eg:- p11 proxy 1 in path 1
	 */
	private String createUserNames(int path, int numOfUsers) {
		String userList = "U";
		for (int i = 1; i < numOfUsers - 1; i++) {
			userList = userList + ", p" + path + i;
		}
		userList = userList + ",V";

		return userList.trim();
	}

	/*
	 * Set all users to be honest initially
	 */
	private String createMalNames(int numOfUsers) {
		String userList = "false";
		for (int i = 1; i < numOfUsers - 1; i++) {
			userList = userList + ", false";
		}

		return userList.trim();
	}

	/*
	 * Convert power-radius value to a time value
	 */
	private double setTDelta() {
		final long C = 299792458L;
		double pradius = Double.parseDouble(power_radius);
		double tDelta = Math.round(pradius / C * 1000000000 * 100.0) / 100.0;

		return tDelta;

	}

}
