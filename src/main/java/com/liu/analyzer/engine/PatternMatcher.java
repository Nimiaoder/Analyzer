package com.liu.analyzer.engine;
import com.liu.analyzer.model.PacketPattern;

public class PatternMatcher {

    public static int indexOf(byte[] payload, PacketPattern pattern) {
        if (payload == null || payload.length == 0) return -1;

        // 如果是 ALL / ?? 模式，直接匹配成功 (回傳 offset 0)
        if (pattern.isCatchAll()) {
            return 0;
        }

        byte[] pBytes = pattern.getPatternBytes();
        byte[] mBytes = pattern.getMaskBytes();
        int pLen = pBytes.length;

        if (payload.length < pLen) return -1;

        int limit = payload.length - pLen;
        for (int i = 0; i <= limit; i++) {
            boolean match = true;
            for (int j = 0; j < pLen; j++) {
                if ((payload[i + j] & mBytes[j]) != (pBytes[j] & mBytes[j])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }
}