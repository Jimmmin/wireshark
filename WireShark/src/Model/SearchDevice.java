package wireshark;
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;


public class SearchDevice {
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
		
	}
}
