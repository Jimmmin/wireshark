package wireshark;
import java.util.ArrayList;
import java.util.Date;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.PcapPacketHandler;

public class method {
	public static void main(String[] args) {
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>(); //����̽��� ���� ������ arraylist�� ����
		StringBuilder errbuf = new StringBuilder(); //���� ó��
		
		int r = Pcap.findAllDevs(allDevs, errbuf); //���� ������ ����̽��� allDevs�� ����. 2��° ���ڴ� ����ó��
		
		if((r==Pcap.NOT_OK) || allDevs.isEmpty()) {
			System.out.println("��Ʈ��ũ ��ġ ã�� ����" + errbuf.toString());
			return;
		} //����ó��
		
		System.out.println("< Ž���� ��Ʈ��ũ Device >");
		int i=0;
		
		for(PcapIf device : allDevs) { //Ž���� ��� ���
			String description = (device.getDescription() != null ) ? device.getDescription() : "��� ���� ������ �����ϴ�.";
			System.out.printf("[%d��]: %s [%s]\n", ++i, device.getName(), description);
		}
		
		PcapIf device = allDevs.get(1);
		System.out.printf("���õ� ��ġ: %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());
		
		int snaplen = 64*1024; //65536Byte��ŭ ��Ŷ ĸ��
		int flags = Pcap.MODE_NON_PROMISCUOUS; //���������
		int timeout = 10*1000;	//Ÿ�Ӿƿ� 10��
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		
		if (pcap == null) {
			System.out.printf("Network Device Access Failed. Error: "+ errbuf.toString());
			return;
		}
		PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>() {
			@Override
				public void nextPacket(PcapPacket packet, String user) {
					Date captureTime = new Date(packet.getCaptureHeader().timestampInMillis());
					int dataLength = packet.getCaptureHeader().caplen();
					System.out.printf("capture time: %s\ncapture length: %d\n", captureTime, dataLength );
			}
		};
		
		//������ ��ü ����
		Ethernet eth = new Ethernet();
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		Payload payload = new Payload();
		PcapHeader header = new PcapHeader(JMemory.POINTER);
		JBuffer buf = new JBuffer(JMemory.POINTER);
		
		
		int id = JRegistry.mapDLTToId(pcap.datalink()); //pcap�� datalink ������ jNetPcap�� �������� id�� ����
		
		while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) { //����� ���۸� �Ǿ
			PcapPacket packet = new PcapPacket(header, buf);
			
			packet.scan(id); //���ο� ��Ŷ�� ��ĵ�Ͽ� ���Ե� ����� ã�´�
			System.out.printf("[ #%d ]\n", packet.getFrameNumber());
			System.out.println("#############packet#############");
			if (packet.hasHeader(eth)) {
				System.out.printf("����� MAC �ּ� = %s\n������ MAC �ּ� = %s\n" ,macSource(packet, eth), macDestination(packet, eth));
			}
			if (packet.hasHeader(ip)) {
				System.out.printf("����� IP �ּ� = %s\n������ IP �ּ� = %s\n" ,ipSource(packet, ip) , ipDestination(packet, ip));
			}
			if (packet.hasHeader(tcp)) {
				System.out.printf("����� TCP �ּ� = %d\n������ TCP �ּ� = %d\n" , tcpSource(packet, tcp), tcpDestination(packet, tcp));
			}
			if (packet.hasHeader(payload)) {
				System.out.printf("���̷ε��� ���� = %d\n", getlength(packet, payload));
				System.out.print(hexdump(packet, payload)); //hexdump ���
			}
			pcap.loop(1, jPacketHandler, "jNetPcap");
			
		}
			
		pcap.close();
	
	}
		
	public static String macSource(PcapPacket packet, Ethernet eth) {
			String source = FormatUtils.mac(eth.source());
			return source;
		}
	public static String macDestination(PcapPacket packet, Ethernet eth) {
		String destination = FormatUtils.mac(eth.destination());
		return destination;
	}
	
	public static String ipSource(PcapPacket packet, Ip4 ip) {
		String source = FormatUtils.ip(ip.source());
		return source;	
		}
	public static String ipDestination(PcapPacket packet, Ip4 ip) {
		String destination = FormatUtils.ip(ip.destination());
		return destination;
	}
	public static int tcpSource(PcapPacket packet, Tcp tcp) {
		return tcp.source();
	}
	
	public static int tcpDestination(PcapPacket packet, Tcp tcp) {
		return tcp.destination();
	}
	
	public static int getlength(PcapPacket packet, Payload payload) {
		return payload.getLength();
	}
	
	public static String hexdump(PcapPacket packet, Payload payload) {
		return payload.toHexdump();
	}
	
}


