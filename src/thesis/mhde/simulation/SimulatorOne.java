package thesis.mhde.simulation;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Properties;

import thesis.mhde.element.*;

public class SimulatorOne {

	private static SimulatorOne instance = new SimulatorOne();

	private static int numOfPaths = 0;
	private static double tDelta = 0.0;
	private static int n;
	private static HashMap<String, String> pathList = new HashMap<String, String>();
	private static HashMap<String, String> delayList = new HashMap<String, String>();
	private static HashMap<String, String> lengthList = new HashMap<String, String>();
	private static HashMap<String, String> malicious = new HashMap<String, String>();
	private static HashMap<String, KeyPair> keysList;

	private Verifier curVerifier;

	private static String secret_K;
	private static PrivateKey esk;

	private SimulatorOne() {
	}

	public static SimulatorOne getInstance() {
		return instance;
	}

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
				lengthList.put("length_" + i, prop.getProperty("length_" + i));
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

	public void simulatePath(int pathNumber) {

		String path = pathList.get("path_" + pathNumber);
		String[] nodes = path.split("\\s*,\\s*");
		String[] linkNames = new String[nodes.length - 1];

		String stringDelays = delayList.get("delay_" + pathNumber);
		String[] del = stringDelays.split("\\s*,\\s*");
		int[] delay = new int[del.length];

		String malLength = malicious.get("mal_" + pathNumber);
		String[] malUsers = malLength.split("\\s*,\\s*");
		boolean[] mal = new boolean[malUsers.length];

		for (int i = 0; i < linkNames.length; i++) {
			linkNames[i] = "link" + i;

			delay[i] = Integer.parseInt(del[i]);

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
				nodesList.add(i, new Prover("U", linksList.get(i), n, keysList.get("U"), secret_K));
			} else if (i == (nodes.length - 1)) {// verifier->0
				nodesList.add(i, curVerifier = new Verifier("V", linksList.get(i - 1), n, path, keysList.get("V"), esk,
						secret_K, "path_" + pathNumber));
			} else {// ->proxies->(2-num of nodes)
				nodesList.add(i, new Proxy(nodes[i].trim(), linksList.get(i - 1), linksList.get(i), n,
						keysList.get(nodes[i].trim())));

			}
		}

		// for (int i = 0; i < nodesList.size(); i++) {
		// if (i > 0 && i < nodesList.size() - 1) {
		// System.out.println(nodes[i] + ": left link= "
		// + nodesList.get(i).getLeftLink().getName()
		// + " right link= "
		// + nodesList.get(i).getRightLink().getName());
		// } else if (i == 0) {
		// System.out.println(nodes[i] + ": right link= "
		// + nodesList.get(i).getRightLink().getName());
		// } else {
		// System.out.println(nodes[i] + ": left link= "
		// + nodesList.get(i).getLeftLink().getName());
		// }
		// }

		for (int i = 0; i < nodesList.size(); i++) {
			new Thread(nodesList.get(i)).start();
		}

	}

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
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// HashMap<String, long[]> times = TrustedThirdParty.getTiming();
		// for (int i = 1; i <= numOfPaths; i++) {
		// long[] t = times.get("path_" + i);
		// if (t != null) {
		// for (long l : t) {
		// System.out.print(l + " ");
		// }
		// System.out.println("");
		// }
		// }

		VerifierProxy vp = new VerifierProxy(numOfPaths, tDelta);
		vp.decideAuthentication();
		vp.estimateDistance();

	}

	public static void main(String[] args) throws InterruptedException {

		String topologyFile = "topologies/topology_1.tpg";

		SimulatorOne so = SimulatorOne.getInstance();
		boolean result = so.readTopology(topologyFile);
		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		keysList = ttp.registerUsers(numOfPaths, pathList, n);
		secret_K = ttp.getSecretK();
		esk = ttp.getVerifierPrivateKey();
		if (result) {
			so.simulateNetwork();
		}

	}

}
