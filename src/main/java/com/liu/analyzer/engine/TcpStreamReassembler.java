package com.liu.analyzer.engine;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TCP 流重組緩衝區 (解決問題 3: 拆包與黏包)
 */
public class TcpStreamReassembler {

    // 最高快取 1MB，避免記憶體溢出
    private static final int MAX_BUFFER_SIZE = 1024 * 1024;

    // 依據 IP:Port 組合建立 Session 緩衝區
    private final Map<String, ByteArrayOutputStream> streamBuffers = new ConcurrentHashMap<>();

    /**
     * 拼接分片封包
     */
    public synchronized byte[] appendAndGetStream(String sessionKey, byte[] incomingPayload) {
        ByteArrayOutputStream buffer = streamBuffers.computeIfAbsent(sessionKey, k -> new ByteArrayOutputStream());

        if (buffer.size() > MAX_BUFFER_SIZE) {
            buffer.reset(); // 超過限制自動清理，重置狀態
        }

        buffer.write(incomingPayload, 0, incomingPayload.length);
        return buffer.toByteArray();
    }

    /**
     * 消耗已成功匹配處理的片段 (滑動視窗)
     */
    public synchronized void consume(String sessionKey, int bytesToConsume) {
        ByteArrayOutputStream buffer = streamBuffers.get(sessionKey);
        if (buffer == null) return;

        byte[] currentData = buffer.toByteArray();
        buffer.reset();

        if (bytesToConsume < currentData.length) {
            int remaining = currentData.length - bytesToConsume;
            buffer.write(currentData, bytesToConsume, remaining);
        }
    }
}