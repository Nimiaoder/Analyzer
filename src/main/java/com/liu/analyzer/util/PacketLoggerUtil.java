package com.liu.analyzer.util;
import com.liu.analyzer.model.PackageInfo;

import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * 封包日誌輸出與解析工具類別
 */
public class PacketLoggerUtil {

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    /**
     * 1. 完整區塊格式化日誌 (Block / Detailed Format)
     * 適合開發測試、視覺化除錯，詳細印出 L2/L3/L4 與 Payload 結構。
     */
    public static void logDetailedBlock(PackageInfo info) {
        String dirIcon = switch (info.direction()) {
            case SEND -> "  [發送 SEND]";
            case RECEIVE -> " [接收 RECV]";
            case UNKNOWN -> " [未知 UNKNOWN]";
        };

        String timeStr = TIME_FORMATTER.format(info.timestamp());
        String srcIp = info.layer3().srcIp();
        String dstIp = info.layer3().dstIp();
        String protocol = info.layer4().transportProtocol();
        String appProtocol = info.layer7().appProtocol();
        int srcPort = info.layer4().srcPort();
        int dstPort = info.layer4().dstPort();
        long seq = info.layer4().sequenceNumber();

        String hexString = info.payload().toHexString();
        int payloadLength = info.payload().length();

        System.out.println("================================================================================");
        System.out.printf("[%s] %s | 傳輸層: %s | 應用層: %s | 大小: %d Bytes\n",
                timeStr, dirIcon, protocol, appProtocol, payloadLength);
        System.out.printf(" ├─ 來源 (Src): %s:%d (MAC: %s)\n", srcIp, srcPort, info.layer2().srcMac());
        System.out.printf(" ├─ 目的 (Dst): %s:%d (MAC: %s)\n", dstIp, dstPort, info.layer2().dstMac());
        if ("TCP".equals(protocol)) {
            System.out.printf(" ├─ TCP 序號 (Seq): %d\n", seq);
        }
        System.out.printf(" └─ Payload (Hex): %s\n", hexString.isEmpty() ? "(無內容)" : hexString);
        System.out.println("================================================================================");
    }

    /**
     * 2. 單行簡潔日誌 (Single Line / Compact Format)
     * 適合高流量、大量封包洗版時的高效即時監控。
     */
    public static void logCompactSingleLine(PackageInfo info) {
        String dir = switch (info.direction()) {
            case SEND -> "OUT";
            case RECEIVE -> "IN";
            case UNKNOWN -> "N/A";
        };
        String timeStr = TIME_FORMATTER.format(info.timestamp());

        System.out.printf("[%s][%s][%s/%s] %s:%d -> %s:%d | Len:%d | Hex: %s\n",
                timeStr,
                dir,
                info.layer4().transportProtocol(),
                info.layer7().appProtocol(),
                info.layer3().srcIp(), info.layer4().srcPort(),
                info.layer3().dstIp(), info.layer4().dstPort(),
                info.payload().length(),
                info.payload().toHexString()
        );
    }

    /**
     * 3. 文字內容/明文解析日誌 (ASCII / Text Content Format)
     * 適合解析帶有 ASCII/UTF-8 文字指令或訊息的封包 Payload。
     */
    public static void logTextContent(PackageInfo info) {
        byte[] raw = info.payload().rawData();
        if (raw == null || raw.length == 0) return;

        String readableAscii = info.payload().toReadableAscii();
        String utf8String = new String(raw, StandardCharsets.UTF_8).replaceAll("\\r|\\n", " ");

        System.out.println("[文字內容解析] 協定: " + info.layer7().appProtocol());
        System.out.println(" ├─ 方向: " + info.direction());
        System.out.println(" ├─ 可讀 ASCII: " + readableAscii);
        System.out.println(" └─ UTF-8 字串: " + utf8String);
    }

    /**
     * 4. JSON 格式輸出日誌 (JSON Event Format)
     * 適合未來丟給 Electron 前端 IPC、WebSocket 或輸出至檔案。
     */
    public static void logAsJson(PackageInfo info) {
        String jsonOutput = String.format("""
            {
              "timestamp": "%s",
              "direction": "%s",
              "protocol": "%s",
              "appProtocol": "%s",
              "src": "%s:%d",
              "dst": "%s:%d",
              "length": %d,
              "payloadHex": "%s"
            }
            """,
                TIME_FORMATTER.format(info.timestamp()),
                info.direction(),
                info.layer4().transportProtocol(),
                info.layer7().appProtocol(),
                info.layer3().srcIp(), info.layer4().srcPort(),
                info.layer3().dstIp(), info.layer4().dstPort(),
                info.payload().length(),
                escapeJson(info.payload().toHexString())
        );

        System.out.println(jsonOutput);
    }

    /** 簡易 JSON 字串跳脫，避免輸出格式被破壞 */
    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}
