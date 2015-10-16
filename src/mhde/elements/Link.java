package mhde.elements;

public class Link {
	
	private String name;
	
	private String leftNode;	
	private String rightNode;
	
	private int data_0;	
	
	private byte[] phase0_data;
	private byte[] phase0_sign;
	
	private String flag="";	
	
	
	private String challenge;
	private String response;

	public Link() {	
		this.setName(null);
	}
	
	public Link(String name, String leftNode, String rightNode){
		this.name=name;
		this.leftNode=leftNode;
		this.rightNode=rightNode;
	}
	
	
	public int getData_0() {
		return data_0;
	}

	public void setData_0(int data_0) {
		this.data_0 = data_0;
	}	
	
	public String getLeftNode() {
		return leftNode;
	}

	public String getRightNode() {
		return rightNode;
	}
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public byte[] getPhase0_data() {
		return phase0_data;
	}

	public void setPhase0_data(byte[] phase0_data) {
		this.phase0_data = phase0_data;
	}

	public byte[] getPhase0_sign() {
		return phase0_sign;
	}

	public void setPhase0_sign(byte[] phase0_sign) {
		this.phase0_sign = phase0_sign;
	}

	public String getFlag() {
		return flag;
	}

	public void setFlag(String flag) {
		this.flag = flag;
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
