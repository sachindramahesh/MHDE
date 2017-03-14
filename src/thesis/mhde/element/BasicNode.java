/**
 * BasicNode.java - An abstract class to create a network node with basic functionalities which are 
 * common for Prover, Verifier and Proxy classes.This class is the parent super class which will be 
 * further extended by ProverOrProxy.java and Verifier.java classes.
 * 
 * @author Mahesh S. Perera
 */

package thesis.mhde.element;

public abstract class BasicNode implements Runnable {
	private String nodeName;// name of the node
	private Link leftLink;// left link of the node
	private Link rightLink;// right link of the node
	private int n;// number of rounds in challenge-response phase

	public BasicNode(String nodeName, Link leftLink, Link rightLink, int n) {
		this.nodeName = nodeName;
		this.leftLink = leftLink;
		this.rightLink = rightLink;
		this.n = n;
	}

	/**
	 * Returns the name of this node
	 * 
	 * @return name of the node
	 */
	public String getNodeName() {
		return nodeName;
	}

	/**
	 * Returns the left link associated with this node
	 * 
	 * @return left link
	 */
	public Link getLeftLink() {
		return leftLink;
	}

	/**
	 * Returns the right link associated with this node
	 * 
	 * @return right link
	 */

	public Link getRightLink() {
		return rightLink;
	}

	/**
	 * Returns the number of challenge-response rounds
	 * 
	 * @return n
	 */
	public int getN() {
		return n;
	}

}
