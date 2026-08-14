package com.liu.analyzer;
import com.liu.analyzer.model.PackageInfo;
import com.liu.analyzer.model.PacketPattern;
import com.liu.analyzer.processor.PackageProcesser;
import com.liu.analyzer.util.NetworkInterfaceUtil;
import com.liu.analyzer.util.PacketLoggerUtil;

import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class Main {

    // 時間格式化工具
    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--list-interfaces".equalsIgnoreCase(args[0])) {
            System.out.println(NetworkInterfaceUtil.getInterfacesAsJson());
            return;
        }

        String targetInterfaceId = null;
        for (int i = 0; i < args.length; i++) {
            if ("--interface".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                targetInterfaceId = args[i + 1];
                break;
            }
        }

        if (targetInterfaceId == null || targetInterfaceId.isBlank()) {
            System.err.println("請指定網卡參數：--interface <GUID>");
            return;
        }

        // 建立單一 Processer 並且綁定各種不同的 Callback 處理寫法
        PackageProcesser processer = new PackageProcesser(targetInterfaceId)
                .register(PacketPattern.TEST_PACKET_1, Main::detailedLogCallback)   // 範例 1: 完整詳細區塊風格
                .register(PacketPattern.TEST_PACKET_2, Main::singleLineLogCallback) // 範例 2: 高效單行 Log 風格
                .register(PacketPattern.TEST_PACKET_3, Main::asciiStringCallback)   // 範例 3: 文字/字串解析風格
                .register(PacketPattern.TEST_CATCH_ALL, Main::jsonFormatCallback);  // 範例 4: 適合丟給前端的 JSON 格式化

        processer.start();
        System.out.println("封包分析器已啟動，開始監聽...");
    }

    // =========================================================================
    // 💡 Callback 實作範例庫 (點餐式選擇你需要的功能)
    // =========================================================================

    /**
     * 【範例 1：詳細排版風格】
     * 適合開發測試、視覺化排版除錯，將所有資訊呈現得非常清楚。
     */
    public static void detailedLogCallback(PackageInfo info) {
        PacketLoggerUtil.logDetailedBlock(info);
    }

    /**
     * 【範例 2：單行日誌風格】
     * 適合大量封包洗版時的高效 Console 印出，資訊緊密。
     */
    public static void singleLineLogCallback(PackageInfo info) {
        PacketLoggerUtil.logCompactSingleLine(info);
    }

    /**
     * 【範例 3：ASCII 內文/字串解析風格】
     * 適合如果封包 Payload 裡面有包含文字（如遊戲聊天、HTTP Header、自訂明文指令）。
     */
    public static void asciiStringCallback(PackageInfo info) {
        PacketLoggerUtil.logTextContent(info);
    }

    /**
     * 【範例 4：前端 JSON 格式化風格】
     * 如果你未來要透過 WebSocket、IPC 或 HTTP 丟給 Electron 前端介面渲染，這樣轉最方便！
     */
    public static void jsonFormatCallback(PackageInfo info) {
        PacketLoggerUtil.logAsJson(info);
    }
}