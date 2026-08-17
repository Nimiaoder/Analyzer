package com.liu.analyzer.engine;
import com.liu.analyzer.model.PackageInfo;
import com.liu.analyzer.model.PacketPattern;
import com.liu.analyzer.util.ProtocolResolver;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * 封包分流與 Event Dispatcher
 *
 * 支援：
 * - 依特徵碼 (PacketPattern) 分流
 * - 依應用層協定 (HTTP / HTTPS / DNS / FTP / SFTP / TCP / UDP ...) 過濾
 * - TCP 串流重組 (解決拆包與黏包)
 */
public class PacketDispatcher {

    /** 一組註冊項目：特徵碼 + 協定過濾條件 + Callback */
    private record Subscription(PacketPattern pattern, Set<String> protocols, Consumer<PackageInfo> handler) {
        boolean matchesProtocol(PackageInfo packet) {
            if (protocols.isEmpty()) return true; // 未指定 = 全協定
            String app = packet.layer7().appProtocol();
            String transport = packet.layer4().transportProtocol();
            return (app != null && protocols.contains(app.toUpperCase(Locale.ROOT)))
                    || (transport != null && protocols.contains(transport.toUpperCase(Locale.ROOT)));
        }
    }

    // 依據註冊順序比對，確保先註冊的 Pattern 先命中
    private final Map<String, Subscription> subscriptions =
            Collections.synchronizedMap(new LinkedHashMap<>());
    private final TcpStreamReassembler tcpReassembler = new TcpStreamReassembler();

    /**
     * 註冊對應特徵碼的 Callback (不限協定)
     */
    public void registerHandler(PacketPattern pattern, Consumer<PackageInfo> handler) {
        registerHandler(pattern, handler, new String[0]);
    }

    /**
     * 註冊對應特徵碼 + 協定過濾的 Callback
     *
     * @param protocols 例如 "HTTP", "HTTPS", "DNS", "FTP", "SFTP", "UDP"；不填代表全部
     */
    public void registerHandler(PacketPattern pattern, Consumer<PackageInfo> handler, String... protocols) {
        Set<String> filter = new LinkedHashSet<>();
        if (protocols != null) {
            Arrays.stream(protocols)
                    .filter(p -> p != null && !p.isBlank())
                    .map(p -> p.trim().toUpperCase(Locale.ROOT))
                    .forEach(filter::add);
        }
        // key = pattern + 協定條件，讓同一個 Pattern 能對不同協定註冊不同處理器
        subscriptions.put(pattern.name() + "@" + filter, new Subscription(pattern, filter, handler));
    }

    /**
     * 處理並分發封包
     */
    public void dispatch(PackageInfo packet) {
        byte[] rawPayload = packet.payload().rawData();
        if (rawPayload == null || rawPayload.length == 0) return;

        String transport = packet.layer4().transportProtocol();

        if (ProtocolResolver.isStreamProtocol(transport)) {
            // TCP：串流重組後再比對 (解決拆包與黏包)
            String sessionKey = String.format("%s:%d->%s:%d",
                    packet.layer3().srcIp(), packet.layer4().srcPort(),
                    packet.layer3().dstIp(), packet.layer4().dstPort());

            byte[] fullStream = tcpReassembler.appendAndGetStream(sessionKey, rawPayload);
            processMatching(packet, fullStream, sessionKey, true);
        } else {
            // UDP / ICMP / 其他 Datagram：直接比對原始 Payload
            processMatching(packet, rawPayload, null, false);
        }
    }

    private void processMatching(PackageInfo packet, byte[] payloadToSearch, String sessionKey, boolean isTcp) {
        Subscription[] snapshot;
        synchronized (subscriptions) {
            snapshot = subscriptions.values().toArray(new Subscription[0]);
        }

        for (Subscription sub : snapshot) {
            if (!sub.matchesProtocol(packet)) continue;

            int matchedIndex = PatternMatcher.indexOf(payloadToSearch, sub.pattern());
            if (matchedIndex != -1) {
                sub.handler().accept(packet);

                if (isTcp && sessionKey != null) {
                    // CATCH_ALL 的 pattern 長度為 0，若只滑動 0 bytes 緩衝區會無限增長，
                    // 因此整段消耗掉。
                    int consumed = sub.pattern().isCatchAll()
                            ? payloadToSearch.length
                            : matchedIndex + sub.pattern().length();
                    tcpReassembler.consume(sessionKey, consumed);
                }
                break; // 命中一個就結束，不再比對後續 Pattern
            }
        }
    }

    /** 清理閒置的 TCP 串流緩衝區 (可由排程定期呼叫) */
    public void evictIdleStreams(long idleMillis) {
        tcpReassembler.evictIdle(idleMillis);
    }
}
