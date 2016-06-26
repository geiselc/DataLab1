
public class Port implements Comparable<Port>{
	private int portN;
	private int amount;
	public Port(int portN, int amount) {
		super();
		this.portN = portN;
		this.amount = amount;
	}
	public int getPortN() {
		return portN;
	}
	public void setPortN(int portN) {
		this.portN = portN;
	}
	public int getAmount() {
		return amount;
	}
	public void setAmount(int amount) {
		this.amount = amount;
	}
	@Override
	public int compareTo(Port p) {
 
		if (this.getAmount() > p.getAmount())
			return 1;
		else if (this.getAmount() < p.getAmount())
			return -1;
		else
			return 0;
	}
}
