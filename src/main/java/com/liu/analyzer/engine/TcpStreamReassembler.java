package com.liu.analyzer.engine;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TCP 流重組緩衝區 (解決拆包與黏包)
 */
public class TcpStreamReassembler {

    // 最高快取 1MB，避免記憶體溢出
    private static final int MAX_BUFFER_SIZE = 1024 * 1024;

    private static final class Session {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        volatile long lastSeen = System.currentTimeMillis();
    }

    // 依據 IP:Port 組合建立 Session 緩衝區
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    /**
     * 拼接分片封包
     */
    public synchronized byte[] appendAndGetStream(String sessionKey, byte[] incomingPayload) {
        Session session = sessions.computeIfAbsent(sessionKey, k -> new Session());
        session.lastSeen = System.currentTimeMillis();

        // 先判斷「加入後」是否會超過上限，避免緩衝區實際超出 MAX_BUFFER_SIZE
        if (session.buffer.size() + incomingPayload.length > MAX_BUFFER_SIZE) {
            session.buffer.reset();
        }

        session.buffer.write(incomingPayload, 0, incomingPayload.length);
        return session.buffer.toByteArray();
    }

    /**
     * 消耗已成功匹配處理的片段 (滑動視窗)
     */
    public synchronized void consume(String sessionKey, int bytesToConsume) {
        Session session = sessions.get(sessionKey);
        if (session == null || bytesToConsume <= 0) return;

        byte[] currentData = session.buffer.toByteArray();
        session.buffer.reset();

        if (bytesToConsume < currentData.length) {
            session.buffer.write(currentData, bytesToConsume, currentData.length - bytesToConsume);
        }
    }

    /**
     * 清除超過指定閒置時間的 Session，防止長時間執行造成記憶體洩漏
     */
    public synchronized void evictIdle(long idleMillis) {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Session>> it = sessions.entrySet().iterator();
        while (it.hasNext()) {
            if (now - it.next().getValue().lastSeen > idleMillis) {
                it.remove();
            }
        }
    }

    /** 目前追蹤中的 Session 數量 */
    public int sessionCount() {
        return sessions.size();
    }
}
