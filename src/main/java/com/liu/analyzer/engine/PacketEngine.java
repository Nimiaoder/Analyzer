package com.liu.analyzer.engine;
import com.liu.analyzer.model.PackageInfo;
import com.liu.analyzer.util.NetworkInterfaceUtil;
import com.liu.analyzer.util.ProtocolResolver;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.time.Instant;
import java.util.Optional;

public class PacketEngine {

    private final String targetInterfaceId;
    private final PacketDispatcher dispatcher;
    private PcapHandle currentHandle; // 保存 Handle 引用以便主動關閉
    private String localIp = "UNKNOWN";

    public PacketEngine(String targetInterfaceId, PacketDispatcher dispatcher) {
        this.targetInterfaceId = targetInterfaceId;
        this.dispatcher = dispatcher;
    }

    /**
     * 啟動監聽 (會被 PackageProcesser 的背景 Thread 呼叫)
     */
    public void start() throws Exception {
        Optional<String> localIpOpt = NetworkInterfaceUtil.getInterfaceIpv4Address(targetInterfaceId);
        this.localIp = localIpOpt.orElse("UNKNOWN");
        System.out.println("成功綁定網卡 IP: " + this.localIp);

        PcapNetworkInterface nif = Pcaps.getDevByName(targetInterfaceId);
        if (nif == null) {
            throw new IllegalArgumentException("找不到指定的網卡裝置: " + targetInterfaceId);
        }

        currentHandle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        currentHandle.setFilter("ip or ip6", BpfProgram.BpfCompileMode.OPTIMIZE);

        // 註冊關閉 Hook (防止強制 Ctrl+C 時資源未釋放)
        Runtime.getRuntime().addShutdownHook(new Thread(this::stop));

        PacketListener listener = rawPacket -> {
            // 使用 Pcap 驅動提供的擷取時間，比 Instant.now() 更精確
            Instant captureTime = currentHandle.getTimestamp() != null
                    ? currentHandle.getTimestamp().toInstant()
                    : Instant.now();
            PackageInfo parsedInfo = parsePacket(rawPacket, this.localIp, captureTime);
            if (parsedInfo != null) {
                dispatcher.dispatch(parsedInfo);
            }
        };

        System.out.println("🚀 封包監聽引擎已就緒...");

        try {
            currentHandle.loop(-1, listener);
        } catch (InterruptedException e) {
            System.out.println("[PacketEngine] 監聽迴圈已被中斷。");
        } catch (NotOpenException ignored) {
            // Handle 已被關閉，正常退出
        }
    }

    /**
     * 主動停止 PacketEngine
     */
    public synchronized void stop() {
        if (currentHandle != null && currentHandle.isOpen()) {
            try {
                currentHandle.breakLoop(); // 中斷 Pcap 迴圈
                currentHandle.close();     // 釋放網卡驅動控制權
                System.out.println("[PacketEngine] 網卡 Handle 已成功釋放！");
            } catch (Exception e) {
                System.err.println("[PacketEngine] 釋放 Handle 時發生異常: " + e.getMessage());
            }
        }
    }

    // === 封包解析邏輯 ===
    private PackageInfo parsePacket(Packet packet, String localIp, Instant captureTime) {
        if (packet == null) return null;

        String srcMac = "N/A", dstMac = "N/A";
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket eth = packet.get(EthernetPacket.class);
            srcMac = eth.getHeader().getSrcAddr().toString();
            dstMac = eth.getHeader().getDstAddr().toString();
        }
        PackageInfo.Layer2Info layer2 = new PackageInfo.Layer2Info(srcMac, dstMac);

        // --- Layer 3 (同時支援 IPv4 / IPv6) ---
        String srcIp = "N/A", dstIp = "N/A", protocolType = "N/A";
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4 = packet.get(IpV4Packet.class);
            srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
            protocolType = ipV4.getHeader().getProtocol().name();
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6 = packet.get(IpV6Packet.class);
            srcIp = ipV6.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV6.getHeader().getDstAddr().getHostAddress();
            protocolType = ipV6.getHeader().getNextHeader().name();
        }
        PackageInfo.Layer3Info layer3 = new PackageInfo.Layer3Info(srcIp, dstIp, protocolType);

        // --- Layer 4 + Payload (直接由傳輸層封包取得，避免多層封裝時取錯) ---
        int srcPort = 0, dstPort = 0;
        String transportProtocol = "OTHER";
        long seqNum = 0;
        byte[] payloadData = new byte[0];

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
            transportProtocol = "TCP";
            seqNum = tcp.getHeader().getSequenceNumberAsLong();
            if (tcp.getPayload() != null) payloadData = tcp.getPayload().getRawData();
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            srcPort = udp.getHeader().getSrcPort().valueAsInt();
            dstPort = udp.getHeader().getDstPort().valueAsInt();
            transportProtocol = "UDP";
            if (udp.getPayload() != null) payloadData = udp.getPayload().getRawData();
        } else if (packet.contains(IcmpV4CommonPacket.class)) {
            transportProtocol = "ICMP";
            IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
            if (icmp.getPayload() != null) payloadData = icmp.getPayload().getRawData();
        } else if (packet.contains(IcmpV6CommonPacket.class)) {
            transportProtocol = "ICMPv6";
            IcmpV6CommonPacket icmp6 = packet.get(IcmpV6CommonPacket.class);
            if (icmp6.getPayload() != null) payloadData = icmp6.getPayload().getRawData();
        } else if (!"N/A".equals(protocolType)) {
            transportProtocol = protocolType;
        }

        PackageInfo.Layer4Info layer4 =
                new PackageInfo.Layer4Info(srcPort, dstPort, transportProtocol, seqNum);

        // --- Layer 7: 應用層協定判別 (HTTP / HTTPS / DNS / FTP / SFTP / ...) ---
        String appProtocol = ProtocolResolver.resolve(transportProtocol, srcPort, dstPort, payloadData);
        PackageInfo.Layer7Info layer7 = new PackageInfo.Layer7Info(appProtocol);

        PackageInfo.PayloadInfo payload = new PackageInfo.PayloadInfo(payloadData);

        PackageInfo.Direction direction = PackageInfo.Direction.UNKNOWN;
        if (!"UNKNOWN".equals(localIp) && !"N/A".equals(srcIp)) {
            if (localIp.equals(srcIp)) {
                direction = PackageInfo.Direction.SEND;
            } else if (localIp.equals(dstIp)) {
                direction = PackageInfo.Direction.RECEIVE;
            }
        }

        return new PackageInfo(captureTime, direction, layer2, layer3, layer4, layer7, payload);
    }
}
