package com.liu.analyzer.model;
import java.time.Instant;

/**
 * 階層化封包資訊模型
 */
public record PackageInfo(
        Instant timestamp,
        Direction direction,
        Layer2Info layer2,
        Layer3Info layer3,
        Layer4Info layer4,
        PayloadInfo payload
) {
    public enum Direction {
        SEND,      // 本機發送 (Outgoing)
        RECEIVE,   // 本機接收 (Incoming)
        UNKNOWN    // 無法判斷
    }

    // === Layer 2: 乙太網層 ===
    public record Layer2Info(String srcMac, String dstMac) {}

    // === Layer 3: 網路層 ===
    public record Layer3Info(String srcIp, String dstIp, String protocolType) {}

    // === Layer 4: 傳輸層 ===
    public record Layer4Info(int srcPort, int dstPort, String transportProtocol, long sequenceNumber) {}

    // === Payload: 應用層數據 (新增 length 與 toReadableAscii) ===
    public record PayloadInfo(byte[] rawData) {

        /**
         * 轉為 16 進位字串 (例: "83 51 42 1E")
         */
        public String toHexString() {
            if (rawData == null || rawData.length == 0) return "";
            StringBuilder sb = new StringBuilder();
            for (byte b : rawData) {
                sb.append(String.format("%02X ", b));
            }
            return sb.toString().trim();
        }

        /**
         * 取得 Payload 位元組長度 (補上這個方法)
         */
        public int length() {
            return rawData != null ? rawData.length : 0;
        }

        /**
         * 轉為乾淨的可讀 ASCII 字串，不可列印字元替換為點 . (補上這個方法)
         * 建議不要用到這個 通常讀不出來
         */
        public String toReadableAscii() {
            if (rawData == null || rawData.length == 0) return "";
            StringBuilder sb = new StringBuilder();
            for (byte b : rawData) {
                if (b >= 32 && b <= 126) {
                    sb.append((char) b);
                } else {
                    sb.append('.');
                }
            }
            return sb.toString();
        }
    }
}