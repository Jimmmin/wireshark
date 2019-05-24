package wireshark;
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;


public class SearchDevice {
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
		
	}
}
