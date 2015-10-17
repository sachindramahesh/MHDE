package mhde.elements;

public class Link {

	private String flag;

	private String name;
	private String leftNode;
	private String rightNode;

	private byte[][] phase0_data = new byte[2][];// array to store path and
													// signature

	private String challenge;
	private String response;

	public Link(String name, String leftNode, String rightNode) {
		this.flag = "";
		this.name = name;
		this.leftNode = leftNode;
		this.rightNode = rightNode;
	}

	public String getFlag() {
		return flag;
	}

	public void setFlag(String flag) {
		this.flag = flag;
	}

	public String getName() {
		return name;
	}

	public String getLeftNode() {
		return leftNode;
	}

	public String getRightNode() {
		return rightNode;
	}

	public byte[][] getPhase0_data() {
		return phase0_data;
	}

	public void setPhase0_data(byte[] path, byte[] sign) {
		this.phase0_data[0] = path;
		this.phase0_data[1] = sign;
	}

	public String getChallenge() {
		return challenge;
	}

	public void setChallenge(String challenge) {
		this.challenge = challenge;
	}

	public String getResponse() {
		return response;
	}

	public void setResponse(String response) {
		this.response = response;
	}

}
