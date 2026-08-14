package com.liu.analyzer.util;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class NetworkInterfaceUtil {

    /**
     * 根據傳入的網卡 ID (targetInterfaceId)，動態抓取該網卡的 IPv4 地址
     *
     * @param targetInterfaceId 驅動層名稱 (例如: \Device\NPF_{...})
     * @return 網卡 IPv4 地址字串，若找不到則回傳 Optional.empty()
     */
    public static Optional<String> getInterfaceIpv4Address(String targetInterfaceId) throws Exception {
        PcapNetworkInterface nif = Pcaps.getDevByName(targetInterfaceId);
        if (nif == null) return Optional.empty();

        return nif.getAddresses().stream()
                .map(PcapAddress::getAddress)
                .filter(addr -> addr instanceof Inet4Address) // 只篩選 IPv4 地址
                .map(InetAddress::getHostAddress)
                .findFirst();
    }

    /**
     * 列出系統所有網卡，並轉為前端易讀的 JSON 格式
     */
    public static String getInterfacesAsJson() throws Exception {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        List<Map<String, String>> result = new ArrayList<>();

        for (PcapNetworkInterface dev : allDevs) {
            String ip = dev.getAddresses().stream()
                    .map(PcapAddress::getAddress)
                    .filter(addr -> addr instanceof Inet4Address)
                    .findFirst()
                    .map(InetAddress::getHostAddress)
                    .orElse("N/A");

            result.add(Map.of(
                    "id", dev.getName(),
                    "description", dev.getDescription() != null ? dev.getDescription() : "N/A",
                    "ip", ip
            ));
        }

        ObjectMapper mapper = new ObjectMapper();
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
    }
}