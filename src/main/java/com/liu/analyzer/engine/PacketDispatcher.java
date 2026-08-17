package com.liu.analyzer.engine;
import com.liu.analyzer.model.PackageInfo;
import com.liu.analyzer.model.PacketPattern;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * 封包分流與 Event Dispatcher (解決問題 4)
 */
public class PacketDispatcher {

    // 依據 put 的順序載入，確保先註冊的 Pattern 先比對
    private final Map<PacketPattern, Consumer<PackageInfo>> handlers = Collections.synchronizedMap(new LinkedHashMap<>());
    private final TcpStreamReassembler tcpReassembler = new TcpStreamReassembler();

    /**
     * 註冊對應特徵碼的 Callback Function
     */
    public void registerHandler(PacketPattern pattern, Consumer<PackageInfo> handler) {
        handlers.put(pattern, handler);
    }

    /**
     * 處理並分發封包
     */
    public void dispatch(PackageInfo packet) {
        byte[] rawPayload = packet.payload().rawData();
        if (rawPayload == null || rawPayload.length == 0) return;

        String transport = packet.layer4().transportProtocol();

        // 針對 TCP 進行流處理 (解決拆包與黏包)
        if ("TCP".equalsIgnoreCase(transport)) {
            String sessionKey = String.format("%s:%d->%s:%d",
                    packet.layer3().srcIp(), packet.layer4().srcPort(),
                    packet.layer3().dstIp(), packet.layer4().dstPort());

            byte[] fullStream = tcpReassembler.appendAndGetStream(sessionKey, rawPayload);
            processMatching(packet, fullStream, sessionKey, true);
        } else {
            // UDP/其他 封包：直接進行 Datagram 匹配
            processMatching(packet, rawPayload, null, false);
        }
    }

    private void processMatching(PackageInfo packet, byte[] payloadToSearch, String sessionKey, boolean isTcp) {
        for (Map.Entry<PacketPattern, Consumer<PackageInfo>> entry : handlers.entrySet()) {
            PacketPattern pattern = entry.getKey();
            Consumer<PackageInfo> handler = entry.getValue();

            int matchedIndex = PatternMatcher.indexOf(payloadToSearch, pattern);
            if (matchedIndex != -1) {
                // 找到特徵碼，觸發對應的 Callback Function
                handler.accept(packet);

                // 若為 TCP，將已處理的資料從 Stream 緩衝區滑出
                if (isTcp && sessionKey != null) {
                    tcpReassembler.consume(sessionKey, matchedIndex + pattern.length());
                }
                break; // 成功一個就直接跳出，不給後續 Pattern 比對
            }
        }
    }
}