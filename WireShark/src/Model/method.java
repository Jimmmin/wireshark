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
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>(); //디바이스를 담을 변수를 arraylist로 생성
		StringBuilder errbuf = new StringBuilder(); //에러 처리
		
		int r = Pcap.findAllDevs(allDevs, errbuf); //접근 가능한 디바이스를 allDevs에 담음. 2번째 인자는 에러처리
		
		if((r==Pcap.NOT_OK) || allDevs.isEmpty()) {
			System.out.println("네트워크 장치 찾기 실패" + errbuf.toString());
			return;
		} //예외처리
		
		System.out.println("< 탐색된 네트워크 Device >");
		int i=0;
		
		for(PcapIf device : allDevs) { //탐색한 장비를 출력
			String description = (device.getDescription() != null ) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
			System.out.printf("[%d번]: %s [%s]\n", ++i, device.getName(), description);
		}
		
		PcapIf device = allDevs.get(1);
		System.out.printf("선택된 장치: %s\n", (device.getDescription() != null) ? device.getDescription() : device.getName());
		
		int snaplen = 64*1024; //65536Byte만큼 패킷 캡쳐
		int flags = Pcap.MODE_NON_PROMISCUOUS; //무차별모드
		int timeout = 10*1000;	//타임아웃 10초
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
		
		//계층별 객체 생성
		Ethernet eth = new Ethernet();
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		Payload payload = new Payload();
		PcapHeader header = new PcapHeader(JMemory.POINTER);
		JBuffer buf = new JBuffer(JMemory.POINTER);
		
		
		int id = JRegistry.mapDLTToId(pcap.datalink()); //pcap의 datalink 유형을 jNetPcap의 프로토콜 id에 맵핑
		
		while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) { //헤더와 버퍼를 피어링
			PcapPacket packet = new PcapPacket(header, buf);
			
			packet.scan(id); //새로운 패킷을 스캔하여 포함된 헤더를 찾는다
			System.out.printf("[ #%d ]\n", packet.getFrameNumber());
			System.out.println("#############packet#############");
			if (packet.hasHeader(eth)) {
				System.out.printf("출발지 MAC 주소 = %s\n도착지 MAC 주소 = %s\n" ,macSource(packet, eth), macDestination(packet, eth));
			}
			if (packet.hasHeader(ip)) {
				System.out.printf("출발지 IP 주소 = %s\n도착지 IP 주소 = %s\n" ,ipSource(packet, ip) , ipDestination(packet, ip));
			}
			if (packet.hasHeader(tcp)) {
				System.out.printf("출발지 TCP 주소 = %d\n도착지 TCP 주소 = %d\n" , tcpSource(packet, tcp), tcpDestination(packet, tcp));
			}
			if (packet.hasHeader(payload)) {
				System.out.printf("페이로드의 길이 = %d\n", getlength(packet, payload));
				System.out.print(hexdump(packet, payload)); //hexdump 출력
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


