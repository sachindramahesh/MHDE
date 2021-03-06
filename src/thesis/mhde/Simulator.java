package thesis.mhde;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Properties;

import thesis.mhde.element.*;

public class Simulator {

	private static Simulator instance = new Simulator();

	private static int numOfPaths = 0;
	private static double tDelta = 0.0;
	private static int n;
	private static HashMap<String, String> pathList = new HashMap<String, String>();
	private static HashMap<String, String> delayList = new HashMap<String, String>();
	//private static HashMap<String, String> lengthList = new HashMap<String, String>();
	private static HashMap<String, String> malicious = new HashMap<String, String>();

	private Verifier curVerifier;

	

	//Singleton-design pattern for Simulator instance
	private Simulator() {
	}

	public static Simulator getInstance() {
		return instance;
	}

	//Read the topology file(converted into propagation delay times) for the network
	public boolean readTopology(String topologyFile) {
		Properties prop = new Properties();
		InputStream inputStream;
		try {
			inputStream = new FileInputStream(topologyFile);
			prop.load(inputStream);
			numOfPaths = Integer.parseInt(prop.getProperty("num_of_paths"));
			n = Integer.parseInt(prop.getProperty("n_value"));
			tDelta = Double.parseDouble(prop.getProperty("t_delta"));
			System.out.println("n value= " + n);
			for (int i = 1; i <= numOfPaths; i++) {
				pathList.put("path_" + i, prop.getProperty("path_" + i));
				delayList.put("delay_" + i, prop.getProperty("delay_" + i));
				//lengthList.put("length_" + i, prop.getProperty("length_" + i));
				malicious.put("mal_" + i, prop.getProperty("mal_" + i));

			}
			for (int i = 1; i <= numOfPaths; i++) {
				System.out.println("path_" + i + "= " + pathList.get("path_" + i));

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
	 * Simulate the MHDE protocol for the single path specified by the parameter 'pathNumber'
	 */
	public void simulatePath(int pathNumber) {

		String path = pathList.get("path_" + pathNumber);
		String[] nodes = path.split("\\s*,\\s*");
		String[] linkNames = new String[nodes.length - 1];

		String stringDelays = delayList.get("delay_" + pathNumber);
		String[] del = stringDelays.split("\\s*,\\s*");
		double[] delay = new double[del.length];

		String malLength = malicious.get("mal_" + pathNumber);
		String[] malUsers = malLength.split("\\s*,\\s*");
		boolean[] mal = new boolean[malUsers.length];

		for (int i = 0; i < linkNames.length; i++) {
			linkNames[i] = "link" + i;

			delay[i] = Double.parseDouble(del[i]);

			mal[i] = Boolean.parseBoolean(malUsers[i]);
		}

		System.out.println("============" + pathNumber + "=" + path + "====================");

		LinkedList<BasicNode> nodesList = new LinkedList<BasicNode>();
		LinkedList<Link> linksList = new LinkedList<Link>();

		String leftNode;
		String rightNode;

		for (int i = 0; i < linkNames.length; i++) {
			leftNode = nodes[i].trim();
			rightNode = nodes[i + 1].trim();
			linksList.add(i, new Link(linkNames[i], leftNode, rightNode,
					delay[i]));
		}

		for (int i = 0; i < nodes.length; i++) {
			if (i == 0) {// prover->1
				nodesList.add(i, new Prover("U", linksList.get(i), n, TrustedThirdParty.getSignKP("U"), TrustedThirdParty.getSecretK()));
			} else if (i == (nodes.length - 1)) {// verifier->0
				nodesList.add(i, curVerifier = new Verifier("V", linksList.get(i - 1), n, path, TrustedThirdParty.getSignKP("V"), TrustedThirdParty.getCipherKP("VC"),
						TrustedThirdParty.getSecretK(), "path_" + pathNumber));
			} else {// ->proxies->(2-num of nodes)
				nodesList.add(i, new Proxy(nodes[i].trim(), linksList.get(i - 1), linksList.get(i), n,
						TrustedThirdParty.getSignKP(nodes[i].trim())));
			}
		}

		for (int i = 0; i < nodesList.size(); i++) {
			new Thread(nodesList.get(i)).start();
		}
	}

	/*
	 * Simulate the MHDE protocol for the whole network.
	 */
	public void simulateNetwork() {
		for (int i = 1; i <= numOfPaths; i++) {
			this.simulatePath(i);
			synchronized (curVerifier) {
				try {
					curVerifier.wait();
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			try {
				Thread.sleep(2000);
				System.out.println("\n\n");
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

		VerifierProxy vp = VerifierProxy.getInstance();
		vp.setNumOfPaths(numOfPaths);
		vp.setTDelta(tDelta);
		vp.decideAuthentication();
		vp.estimateDistance();
	}

	/*
	 * main() method that runs the simulation programme
	 */
	public static void main(String[] args) throws InterruptedException {

		String topologyFile = "inputs/topologyin.tpg";
		ConvertFile cf=new ConvertFile();
		cf.readTopology(topologyFile);
		cf.createTopologyFile("inputs/topologyout.tpg");

		Simulator so = Simulator.getInstance();
		boolean result = so.readTopology("inputs/topologyout.tpg");	
		
		if (result) {
			TrustedThirdParty.registerUsers(numOfPaths, pathList, n);
			so.simulateNetwork();
		}
	}

}
