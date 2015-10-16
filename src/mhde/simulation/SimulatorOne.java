package mhde.simulation;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Properties;

import mhde.elements.Link;
import mhde.elements.Node;
import mhde.elements.Prover;
import mhde.elements.Proxy;
import mhde.elements.Verifier;
import mhde.elements.TrustedThirdParty;

public class SimulatorOne {

	private static SimulatorOne instance = new SimulatorOne();

	private static int numOfPaths;
	//private static int numOfNodes;
	private static int n;
	private static HashMap<String, String> pathList;
	//private static LinkedList<KeyPair> keyList;
	private static HashMap<String, KeyPair> keysList;
	
	private Verifier curVerifier;
	
	private static String secret_K;
	private static PrivateKey esk;

	private SimulatorOne() {
		numOfPaths = 0;
		//numOfNodes = 0;
		pathList = new HashMap<String, String>();
		//keyList = null;

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
			//numOfNodes = Integer.parseInt(prop.getProperty("num_of_nodes"));
			n = Integer.parseInt(prop.getProperty("n_value"));
			
			System.out.println("n value= "+n);

			for (int i = 1; i <= numOfPaths; i++) {
				pathList.put("path_" + i, prop.getProperty("path_" + i));
			}

			for (int i = 1; i <= numOfPaths; i++) {
				System.out.println("path_" + i + "= "
						+ pathList.get("path_" + i));
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

	public void simulatePath(String pathNumber) {

		String path = pathList.get(pathNumber);
		String[] nodes = path.split("\\s*,\\s*");
		String[] linkNames = new String[nodes.length - 1];
		
		for (int i = 0; i < linkNames.length; i++) {
			linkNames[i]="link"+i;
		}

		System.out.println("============" + pathNumber+"="+path + "====================");

		LinkedList<Node> nodesList = new LinkedList<Node>();
		LinkedList<Link> linksList = new LinkedList<Link>();

		String leftNode;
		String rightNode;
		
		for (int i = 0; i < linkNames.length; i++) {
			leftNode=nodes[i].trim();
			rightNode=nodes[i+1].trim();
			linksList.add(i, new Link(linkNames[i],leftNode,rightNode));
		}

		for (int i = 0; i < nodes.length; i++) {
			if (i == 0) {//prover->1
				nodesList.add(i, new Prover("U",linksList.get(i), keysList.get("U"),n,secret_K));
			} else if (i == (nodes.length - 1)) {//verifier->0
				nodesList.add(i,
						curVerifier=new Verifier("V",linksList.get(i - 1), keysList.get("V"),path, n,secret_K,esk));
			} else {//->proxies->(2-num of nodes)
				nodesList.add(i,
						new Proxy(nodes[i].trim(), linksList.get(i - 1), linksList.get(i), keysList.get(nodes[i].trim()),n));
			}
		}

		for (int i = 0; i < nodesList.size(); i++) {
			if (i > 0 && i < nodesList.size() - 1) {
				System.out.println(nodes[i] + ": left link= "
						+ nodesList.get(i).getLeftLink().getName()
						+ "  right link= "
						+ nodesList.get(i).getRightLink().getName());
			} else if (i == 0) {
				System.out.println(nodes[i] + ": right link= "
						+ nodesList.get(i).getRightLink().getName());
			} else {
				System.out.println(nodes[i] + ": left link= "
						+ nodesList.get(i).getLeftLink().getName());
			}
		}

		for (int i = 0; i < nodesList.size(); i++) {
			new Thread(nodesList.get(i)).start();
		}

	}

	public void simulateNetwork() {

		for (int i = 1; i <= numOfPaths ; i++) {
			/*this.simulatePath("path_" + i);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}*/
			this.simulatePath("path_" + i);	
			
			synchronized (curVerifier) {
				try {
					curVerifier.wait();
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				
			}
		}
	}

	public static void main(String[] args) throws InterruptedException {
		
		String topologyFile="topologies/topology_1.tpg";
		// SimulatorOne so = new SimulatorOne();
		SimulatorOne so = SimulatorOne.getInstance();
		boolean result = so.readTopology(topologyFile);
		TrustedThirdParty ttp = TrustedThirdParty.getInstance();
		keysList=ttp.registerUsers(numOfPaths, pathList,n);
		secret_K=ttp.getSecretK();
		esk=ttp.getVerifierPrivateKey();
		if (result) {
			//so.simulateNetwork();
			so.simulatePath("path_1");
		}

	}

}
