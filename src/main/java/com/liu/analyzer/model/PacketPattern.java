package com.liu.analyzer.model;
public enum PacketPattern {

    // === 測試相關特徵碼定義 ===
    TEST_PACKET_1("83 51 42 1E ?? ?? ?? FF 31", "測試1"),
    TEST_PACKET_2("83 51 42 2A ?? ?? 10 00", "測試2"),
    TEST_PACKET_3("83 51 42 3F ?? FF 05", "測試3"),

    // 全攔截模式
    TEST_CATCH_ALL("ALL", "測試all");

    private final String patternStr;
    private final String description;
    private final byte[] patternBytes;
    private final byte[] maskBytes;
    private final boolean isCatchAll;

    PacketPattern(String patternStr, String description) {
        this.patternStr = patternStr;
        this.description = description;

        if ("ALL".equalsIgnoreCase(patternStr.trim()) || "??".equals(patternStr.trim())) {
            this.isCatchAll = true;
            this.patternBytes = new byte[0];
            this.maskBytes = new byte[0];
            return;
        }

        this.isCatchAll = false;
        String[] tokens = patternStr.split("\\s+");
        this.patternBytes = new byte[tokens.length];
        this.maskBytes = new byte[tokens.length];

        for (int i = 0; i < tokens.length; i++) {
            if ("??".equals(tokens[i])) {
                this.patternBytes[i] = (byte) 0x00;
                this.maskBytes[i] = (byte) 0x00;
            } else {
                this.patternBytes[i] = (byte) Integer.parseInt(tokens[i], 16);
                this.maskBytes[i] = (byte) 0xFF;
            }
        }
    }

    public String getPatternStr() { return patternStr; }
    public String getDescription() { return description; }
    public byte[] getPatternBytes() { return patternBytes; }
    public byte[] getMaskBytes() { return maskBytes; }
    public boolean isCatchAll() { return isCatchAll; }
    public int length() { return patternBytes.length; }
}