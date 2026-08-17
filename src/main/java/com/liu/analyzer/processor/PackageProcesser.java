package com.liu.analyzer.processor;
import com.liu.analyzer.engine.PacketDispatcher;
import com.liu.analyzer.engine.PacketEngine;
import com.liu.analyzer.model.PackageInfo;
import com.liu.analyzer.model.PacketPattern;

import java.util.function.Consumer;

public class PackageProcesser {

    private final PacketDispatcher dispatcher;
    private final PacketEngine engine;
    private Thread workerThread;
    private volatile boolean isRunning = false;

    public PackageProcesser(String targetInterfaceId) {
        this.dispatcher = new PacketDispatcher();
        this.engine = new PacketEngine(targetInterfaceId, this.dispatcher);
    }

    /**
     * 註冊特徵碼與對應的 Callback 處理邏輯
     */
    public PackageProcesser register(PacketPattern pattern, Consumer<PackageInfo> handler) {
        this.dispatcher.registerHandler(pattern, handler);
        return this; // 支援鏈式呼叫 (Fluent API)
    }

    /**
     * 異步 / 非阻塞式啟動 (在背景 Thread 中啟動監聽，不會卡住 Main Thread)
     */
    public synchronized void start() {
        if (isRunning) {
            System.out.println(" [PackageProcesser] 監聽服務已經在運行中！");
            return;
        }

        isRunning = true;
        workerThread = new Thread(() -> {
            try {
                System.out.println("⚡ [PackageProcesser] 異步背景執行序啟動中...");
                engine.start(); // 調用底層 PacketEngine 的 Blocking loop
            } catch (Exception e) {
                if (isRunning) {
                    System.err.println(" [PackageProcesser] 監聽引擎運行異常: " + e.getMessage());
                }
            } finally {
                isRunning = false;
            }
        }, "PacketProcesser-Worker");

        workerThread.start();
    }

    /**
     * 主動停止監聽引擎並釋放網卡資源
     */
    public synchronized void stop() {
        if (!isRunning) {
            System.out.println(" [PackageProcesser] 監聽服務未啟動或已停止。");
            return;
        }

        System.out.println(" [PackageProcesser] 收到停止指令，正在中斷監聽並釋放網卡...");
        isRunning = false;

        // 調用 PacketEngine 內部的關閉邏輯
        engine.stop();

        // 中斷背景 Worker Thread
        if (workerThread != null && workerThread.isAlive()) {
            workerThread.interrupt();
        }
        System.out.println(" [PackageProcesser] 監聽服務已成功停止！");
    }

    public boolean isRunning() {
        return isRunning;
    }
}