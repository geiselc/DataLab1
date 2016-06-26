import java.util.Arrays;
import java.util.HashMap;


public class Data {
    int iEEE = 0;
    int e2 = 0;
    int tcp = 0;
    int udp = 0;
    int icmp = 0;
    int i4 = 0;
    int comboTotal = 0;
    HashMap<Integer, Integer> step2;
    HashMap<Integer, Integer> step3;
    HashMap<String, Integer> step5;
    int totalB;
    HashMap<Integer, Integer> tcpS;
    HashMap<Integer, Integer> tcpD;
    HashMap<Integer, Integer> udpS;
    HashMap<Integer, Integer> udpD;
    
    public Data() {
        step2 = new HashMap<Integer, Integer>();
        step3 = new HashMap<Integer, Integer>();
        step5 = new HashMap<String, Integer>();
        
        tcpS = new HashMap<Integer, Integer>();
        tcpD = new HashMap<Integer, Integer>();
        udpS = new HashMap<Integer, Integer>();
        udpD = new HashMap<Integer, Integer>();
    }
    
    public int getiEEE() {
        return iEEE;
    }
    public void setiEEE(int iEEE) {
        this.iEEE = iEEE;
    }
    public int getE2() {
        return e2;
    }
    public void setE2(int e2) {
        this.e2 = e2;
    }

    public HashMap<Integer, Integer> getStep2() {
        return step2;
    }

    public void setStep2(HashMap<Integer, Integer> step2) {
        this.step2 = step2;
    }

    public HashMap<Integer, Integer> getStep3() {
        return step3;
    }

    public void setStep3(HashMap<Integer, Integer> step3) {
        this.step3 = step3;
    }
    
    public HashMap<String, Integer> getStep5(){
    	return step5;
    }
    
    public void setStep5(HashMap<String, Integer> step5){
    	this.step5 = step5;
    }
    
    public int getComboTotal(){
    	return comboTotal;
    }
    
    public void setComboTotal(int comboTotal){
    	this.comboTotal = comboTotal;
    }

    public int getTotalB() {
        return totalB;
    }

    public void setTotalB(int totalB) {
        this.totalB = totalB;
    }

    public int getTcp() {
        return tcp;
    }

    public void setTcp(int tcp) {
        this.tcp = tcp;
    }

    public int getUdp() {
        return udp;
    }

    public void setUdp(int udp) {
        this.udp = udp;
    }

    public int getIcmp() {
        return icmp;
    }

    public void setIcmp(int icmp) {
        this.icmp = icmp;
    }

    public int getI4() {
        return i4;
    }

    public void setI4(int i4) {
        this.i4 = i4;
    }

	public HashMap<Integer, Integer> getTcpS() {
		return tcpS;
	}

	public void setTcpS(HashMap<Integer, Integer> tcpS) {
		this.tcpS = tcpS;
	}

	public HashMap<Integer, Integer> getTcpD() {
		return tcpD;
	}

	public void setTcpD(HashMap<Integer, Integer> tcpD) {
		this.tcpD = tcpD;
	}

	public HashMap<Integer, Integer> getUdpS() {
		return udpS;
	}

	public void setUdpS(HashMap<Integer, Integer> udpS) {
		this.udpS = udpS;
	}

	public HashMap<Integer, Integer> getUdpD() {
		return udpD;
	}

	public void setUdpD(HashMap<Integer, Integer> udpD) {
		this.udpD = udpD;
	}
    
    public Port[] sortPort(HashMap<Integer, Integer> map) {
    	Object[] keys = map.keySet().toArray();
    	Port[] ports = new Port[keys.length];
    	
    	// change map to array
    	for (int i = 0; i < keys.length; i++) {
    		int p = (Integer) keys[i];
    		int amount = map.get(p);
    		Port port = new Port(p, amount);
    		ports[i] = port;
    	}
    	
    	// sort array
    	Arrays.sort(ports, new PortCompare());
		return ports;
    	
    }
    
}