package thesis.mhde.element;

public abstract class BasicNode implements Runnable {
	private String nodeName;
	private Link leftLink;
	private Link rightLink;
	private int n;

	
	
	public BasicNode(String nodeName, Link leftLink, Link rightLink, int n) {
		this.nodeName = nodeName;
		this.leftLink = leftLink;
		this.rightLink = rightLink;
		this.n = n;
	}

	public String getNodeName() {
		return nodeName;
	}

	public Link getLeftLink() {
		return leftLink;
	}

	public Link getRightLink() {
		return rightLink;
	}

	public int getN() {
		return n;
	}

}
