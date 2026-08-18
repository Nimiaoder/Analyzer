package com.liu.analyzer.util;

import java.util.Map;

/**
 * 應用層協定判別工具 (Layer 7)
 *
 * 判別順序：
 * 1. Payload 特徵 (Signature) —— 最準確，可辨識非標準埠號
 * 2. 標準埠號對照表 (Well-known ports)
 * 3. 回退為傳輸層協定名稱 (TCP / UDP / ICMP ...)
 */
public final class ProtocolResolver {

    private ProtocolResolver() {}

    /** TCP 常見埠號對照 */
    private static final Map<Integer, String> TCP_PORTS = Map.ofEntries(
            Map.entry(20, "FTP-DATA"),
            Map.entry(21, "FTP"),
            Map.entry(22, "SFTP"),      // SFTP / SCP / SSH 皆走 22
            Map.entry(23, "TELNET"),
            Map.entry(25, "SMTP"),
            Map.entry(53, "DNS"),
            Map.entry(80, "HTTP"),
            Map.entry(110, "POP3"),
            Map.entry(143, "IMAP"),
            Map.entry(443, "HTTPS"),
            Map.entry(465, "SMTPS"),
            Map.entry(587, "SMTP"),
            Map.entry(990, "FTPS"),
            Map.entry(993, "IMAPS"),
            Map.entry(995, "POP3S"),
            Map.entry(1433, "MSSQL"),
            Map.entry(3306, "MYSQL"),
            Map.entry(3389, "RDP"),
            Map.entry(5432, "POSTGRESQL"),
            Map.entry(5671, "AMQPS"),
            Map.entry(5672, "AMQP"),
            Map.entry(6379, "REDIS"),
            Map.entry(8080, "HTTP"),
            Map.entry(8000, "HTTP"),
            Map.entry(8443, "HTTPS"),
            Map.entry(27017, "MONGODB")
    );

    /** UDP 常見埠號對照 */
    private static final Map<Integer, String> UDP_PORTS = Map.ofEntries(
            Map.entry(53, "DNS"),
            Map.entry(67, "DHCP"),
            Map.entry(68, "DHCP"),
            Map.entry(69, "TFTP"),
            Map.entry(123, "NTP"),
            Map.entry(137, "NETBIOS"),
            Map.entry(138, "NETBIOS"),
            Map.entry(161, "SNMP"),
            Map.entry(162, "SNMP"),
            Map.entry(443, "QUIC"),     // HTTP/3
            Map.entry(500, "ISAKMP"),
            Map.entry(514, "SYSLOG"),
            Map.entry(1900, "SSDP"),
            Map.entry(3478, "STUN"),
            Map.entry(5060, "SIP"),
            Map.entry(5353, "MDNS")
    );

    private static final String[] HTTP_METHODS = {
            "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "
    };

    /**
     * 判別應用層協定。
     *
     * @param transport 傳輸層協定 (TCP / UDP / ICMP / ...)
     * @param srcPort   來源埠 (無埠號時傳 0)
     * @param dstPort   目的埠 (無埠號時傳 0)
     * @param payload   應用層資料 (可為 null)
     * @return 協定名稱，例如 HTTP / HTTPS / DNS / FTP / SFTP / TCP
     */
    public static String resolve(String transport, int srcPort, int dstPort, byte[] payload) {
        if (transport == null) transport = "UNKNOWN";

        // 1) Payload 特徵優先 (可辨識跑在非標準埠上的服務)
        String bySignature = resolveBySignature(transport, payload);
        if (bySignature != null) return bySignature;

        // 2) 埠號對照 (以較小的埠號優先，通常為 Server 端)
        Map<Integer, String> table = switch (transport.toUpperCase()) {
            case "TCP" -> TCP_PORTS;
            case "UDP" -> UDP_PORTS;
            default -> Map.of();
        };
        String byServerPort = table.get(Math.min(srcPort, dstPort) == 0
                ? Math.max(srcPort, dstPort)
                : Math.min(srcPort, dstPort));
        if (byServerPort != null) return byServerPort;

        String bySrc = table.get(srcPort);
        if (bySrc != null) return bySrc;
        String byDst = table.get(dstPort);
        if (byDst != null) return byDst;

        // 3) 回退傳輸層名稱
        return transport;
    }

    /** 依照 Payload 開頭位元組進行特徵比對 */
    private static String resolveBySignature(String transport, byte[] payload) {
        if (payload == null || payload.length < 3) return null;

        boolean isTcp = "TCP".equalsIgnoreCase(transport);

        // TLS Record: 0x16 (Handshake) + 0x03 0x00~0x04 (SSL3/TLS1.x)
        if (isTcp && payload[0] == 0x16 && payload[1] == 0x03 && payload[2] >= 0x00 && payload[2] <= 0x04) {
            return "HTTPS";
        }

        String head = asciiHead(payload, 16);

        // SSH / SFTP 交握: "SSH-2.0-..."
        if (head.startsWith("SSH-")) return "SFTP";

        if (isTcp) {
            if (head.startsWith("HTTP/1.") || head.startsWith("HTTP/2")) return "HTTP";
            for (String m : HTTP_METHODS) {
                if (head.startsWith(m)) return "HTTP";
            }
            // FTP 控制通道: 三位數狀態碼 或 常見指令
            if (head.matches("^\\d{3}[ -].*") ) return "FTP";
            if (head.startsWith("USER ") || head.startsWith("PASS ") || head.startsWith("RETR ")
                    || head.startsWith("STOR ") || head.startsWith("PASV") || head.startsWith("EPSV")
                    || head.startsWith("LIST")) {
                return "FTP";
            }
        }
        return null;
    }

    private static String asciiHead(byte[] data, int max) {
        int len = Math.min(max, data.length);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            byte b = data[i];
            sb.append(b >= 32 && b <= 126 ? (char) b : '.');
        }
        return sb.toString();
    }

    /** 該協定是否為需要做 TCP 串流重組的位元組流協定 */
    public static boolean isStreamProtocol(String transport) {
        return "TCP".equalsIgnoreCase(transport);
    }
}
