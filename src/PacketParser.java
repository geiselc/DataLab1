import java.math.RoundingMode;
import java.text.DecimalFormat;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot1q;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class PacketParser {

	private Data d;

	public static void main(String[] args) {
		if (args.length == 1) {
			PacketParser pp = new PacketParser();
			pp.parse(args[0]);
			pp.print();
		} else {
			System.out
					.println("This program only takes one argument that is a pcap file");
		}
	}

	public PacketParser() {
		d = new Data();
	}

	public void parse(String fileName) {

		// set up errBuf and file
		final StringBuilder errbuf = new StringBuilder();
		final String file = fileName;

		// open the file and make sure it isnt null
		Pcap pcap = Pcap.openOffline(file, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}

		// create the packet handler
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			Ip4 ip4 = new Ip4();
			Ip6 ip6 = new Ip6();
			Arp arp = new Arp();
			IEEE802dot1q ie1 = new IEEE802dot1q();
			IEEE802dot2 ie2 = new IEEE802dot2();
			IEEE802dot3 ie3 = new IEEE802dot3();

			// run for each packet
			public void nextPacket(PcapPacket packet, String notUsed) {
				if (packet.hasHeader(ie1) || packet.hasHeader(ie2)
						|| packet.hasHeader(ie3)) {
					d.setiEEE(1 + d.getiEEE());
				} else {
					boolean e = false;
					if (packet.hasHeader(ip4)) {
						d.setE2(d.getE2() + 1);
						d.setI4(d.getI4() + 1);
						e = true;

						if (packet.hasHeader(new Tcp())) {
							d.setTcp(d.getTcp() + 1);

							int source = packet.getHeader(new Tcp()).source();
							int dest = packet.getHeader(new Tcp())
									.destination();

							if (d.getTcpS().containsKey(source) == false) {
								d.getTcpS().put(source, 1);
							} else {
								d.getTcpS().put(source,
										d.getTcpS().get(source) + 1);
							}

							if (d.getTcpD().containsKey(dest) == false) {
								d.getTcpD().put(dest, 1);
							} else {
								d.getTcpD()
										.put(dest, d.getTcpD().get(dest) + 1);
							}

						} else if (packet.hasHeader(new Udp())) {
							d.setUdp(d.getUdp() + 1);

							int source = packet.getHeader(new Udp()).source();
							int dest = packet.getHeader(new Udp())
									.destination();

							if (d.getUdpS().containsKey(source) == false) {
								d.getUdpS().put(source, 1);
							} else {
								d.getUdpS().put(source,
										d.getUdpS().get(source) + 1);
							}

							if (d.getUdpD().containsKey(dest) == false) {
								d.getUdpD().put(dest, 1);
							} else {
								d.getUdpD()
										.put(dest, d.getUdpD().get(dest) + 1);
							}
						} else if (packet.hasHeader(new Icmp())) {
							d.setIcmp(d.getIcmp() + 1);
						} else {

						}
					} else if (packet.hasHeader(ip6)) {
						d.setE2(d.getE2() + 1);
						e = true;
					} else if (packet.hasHeader(arp)) {
						d.setE2(d.getE2() + 1);
						e = true;
					} else {
						if (packet.hasHeader(new Ethernet())) {
							int hex = packet.getHeader(new Ethernet()).type();

							if (hex > 1536) {
								d.setE2(d.getE2() + 1);
								e = true;
							} else {
								d.setiEEE(1 + d.getiEEE());
							}
						}
					}
					if (e) {
						int hex = packet.getHeader(new Ethernet()).type();

						// step 2
						if (d.getStep2().containsKey(hex) == false) {
							d.getStep2().put(hex, 1);
						} else {
							d.getStep2().put(hex, d.getStep2().get(hex) + 1);
						}

						// step 3

						int len = 0;
						if (packet.hasHeader(ip4)) {
							len = packet.getHeader(ip4).length();

							// step 5
							String sAddress = org.jnetpcap.packet.format.FormatUtils
									.ip(ip4.source());
							String dAddress = org.jnetpcap.packet.format.FormatUtils
									.ip(ip4.destination());
							String addressCombo = "Source: " + sAddress
									+ ", Destination: " + dAddress;

							if (d.getStep5().containsKey(addressCombo) == false) {
								d.getStep5().put(addressCombo, 1);
							} else {
								d.getStep5().put(addressCombo,
										d.getStep5().get(addressCombo) + 1);
							} // end step 5
						} else if (packet.hasHeader(ip6)) {
							len = packet.getHeader(ip6).length();
						} else if (packet.hasHeader(arp)) {
							len = packet.getHeader(arp).getLength();
						} else {
							len = packet.remaining(packet.getCaptureHeader().size());
						}

						if (d.getStep3().containsKey(hex) == false) {
							d.getStep3().put(hex, len);
						} else {
							d.getStep3().put(hex, d.getStep3().get(hex) + len);
						}
						d.setTotalB(d.getTotalB() + len);
					}
				}
			}
		};

		// loop 500 times through the pcap file
		// calling nextPacket for each packet
		try {
			pcap.loop(500, jpacketHandler, "");
		} finally {
			pcap.close();
		}
	}

	private void portPrint(Port[] port, boolean tcp) {
		DecimalFormat df = new DecimalFormat("####0.00");
		df.setRoundingMode(RoundingMode.HALF_UP);

		for (int i = 0; i < 5 && i < port.length; i++) {
			int p = port[i].getPortN();
			int a = port[i].getAmount();
			int total = tcp ? d.getTcp() : d.getUdp();
			double per = ((a * 1.0) / (total * 1.0)) * 100.0;
			System.out.println((i + 1) + ": " + p + " - " + df.format(per)
					+ "%");
		}
	}

	public void print() {

		DecimalFormat df = new DecimalFormat("####0.00");
		df.setRoundingMode(RoundingMode.HALF_UP);

		// step 1
		System.out.print("Percentages of packets using IEEE 802.3 Ethernet: ");
		System.out.println(df.format(((d.getiEEE() / 500.0) * 100.0)) + "%");
		System.out.print("Percentages of packets using Ethernet II: ");
		System.out.println(df.format(((d.getE2() / 500.0) * 100.0)) + "%");

		// step 2
		System.out
				.println("\nEthernet Type Value (in hex) and percent of type in Ethernet II packets");
		Object[] keys = d.getStep2().keySet().toArray();
		for (int i = 0; i < keys.length; i++) {
			int hex = (Integer) keys[i];
			String h = Integer.toHexString(hex);
			if (h.length() == 3) {
				h = "0x0" + h;
			} else {
				h = "0x" + h;
			}
			String v = df.format(d.getStep2().get(hex) / (d.getE2() * 1.0)
					* 100)
					+ "";
			System.out.println(h + " - " + v + "%");
		}

		// step 3 : total bytes
		System.out
				.println("\nEthernet Type Value (in hex), bytes and percent of total bytes transferred using each network layer");
		keys = d.getStep3().keySet().toArray();
		for (int i = 0; i < keys.length; i++) {
			int hex = (Integer) keys[i];
			String t = Integer.toHexString(hex) + "";
			if (t.length() == 3) {
				t = "0x0" + t;
			} else {
				t = "0x" + t;
			}
			String b = d.getStep3().get(hex) + "";
			String p = df
					.format((d.getStep3().get(hex) / (d.getTotalB() * 1.0)) * 100)
					+ "%";
			System.out.println(t + " - " + b + " - " + p);
		}

		// step 4
		System.out
				.println("\nPercent of IPv4 packets each address pair is responsible for:");
		Set<String> addresses = d.step5.keySet();
		for (String key : addresses) {
			System.out.print("Address Pair " + key);
			System.out.print(" accounts for "
					+ df.format(((d.step5.get(key) / (d.getI4() / 100.0)) * 1))
					+ "%\n");
		}

		// step 5
		System.out
				.println("\nPercent of IPv4 packets using a given transport layer");
		System.out.println("TCP - "
				+ df.format(((d.getTcp() / (d.getI4() / 100.0)) * 1)) + "%");
		System.out.println("UDP - "
				+ df.format(((d.getUdp() / (d.getI4() / 100.0)) * 1)) + "%");
		System.out.println("ICMP - "
				+ df.format(((d.getIcmp() / (d.getI4() / 100.0)) * 1)) + "%");

		// step 6
		System.out
				.println("\nFive most often seen source TCP ports and percent of TCP traffic the port is seen in");
		Port[] port = d.sortPort(d.getTcpS());
		portPrint(port, true);

		System.out
				.println("\nFive most often seen destination TCP ports and percent of TCP traffic the port is seen in");
		port = d.sortPort(d.getTcpD());
		portPrint(port, true);

		System.out
				.println("\nFive most often seen source UDP ports and percent of UDP traffic the port is seen in");
		port = d.sortPort(d.getUdpS());
		portPrint(port, false);

		System.out
				.println("\nFive most often seen destination UDP ports and percent of UDP traffic the port is seen in");
		port = d.sortPort(d.getUdpD());
		portPrint(port, false);
	}
}