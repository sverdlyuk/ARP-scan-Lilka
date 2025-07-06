#include <lilka.h>
#include "ipapp.h"
#include "servicemanager.h"
#include "services/network.h"
 
extern "C" {
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
}
 
IPApp::IPApp() : App("IP Address") {}
 
void IPApp::scanNetwork(std::vector<String>& results) {
    struct netif* netif = netif_list;
    IPAddress localIP = WiFi.localIP();
    uint8_t subnet[4] = { localIP[0], localIP[1], localIP[2], 0 };
 
    // Відправляємо ARP-запити до всіх адрес у підмережі
    for (int i = 1; i <= 254; ++i) {
        ip4_addr_t target_ip;
        subnet[3] = i;
        IPAddress ip(subnet[0], subnet[1], subnet[2], subnet[3]);
        ip4addr_aton(ip.toString().c_str(), &target_ip);
        etharp_request(netif, &target_ip);
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
    vTaskDelay(1000 / portTICK_PERIOD_MS);
 
    // Збираємо знайдені IP–MAC
    for (int i = 1; i <= 254; ++i) {
        subnet[3] = i;
        IPAddress ip(subnet[0], subnet[1], subnet[2], subnet[3]);
        ip4_addr_t target_ip;
        ip4addr_aton(ip.toString().c_str(), &target_ip);
        struct eth_addr *eth_ret;
        const ip4_addr_t *ip_ret;
        if (etharp_find_addr(netif, &target_ip, &eth_ret, &ip_ret) >= 0) {
            char macbuf[18];
            snprintf(macbuf, sizeof(macbuf), "%02X:%02X:%02X:%02X:%02X:%02X",
                eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
                eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
            results.push_back(ip.toString() + " - " + String(macbuf));
        }
    }
}
 
const char* lookupVendor(const uint8_t mac[6]);
 
void IPApp::run() {
    std::vector<String> arpResults;
    scanNetwork(arpResults);
 
    lilka::Menu menu("ARP scan");
    menu.addActivationButton(lilka::Button::B); // Back
    menu.addActivationButton(lilka::Button::C);
    if (arpResults.empty()) {
        menu.addItem("No devices found");
    } else {
        for (const auto& entry : arpResults) {
            menu.addItem(entry);
        }
    }
    menu.addItem("Оновити");
    menu.addItem("Назад");
    int count = (int)arpResults.size() + 2;
    if (arpResults.empty()) count = 3;
 
    while (true) {
        while (!menu.isFinished()) {
            menu.update();
            menu.draw(canvas);
            queueDraw();
        }
        int cursor = menu.getCursor();
        if (cursor == count - 1 || menu.getButton() == lilka::Button::B) {
            return;
        }
        if (cursor == count - 2) { // Оновити
            arpResults.clear();
            menu.clearItems();
            scanNetwork(arpResults);
            if (arpResults.empty()) {
                menu.addItem("No devices found");
            } else {
                for (const auto& entry : arpResults) {
                    menu.addItem(entry);
                }
            }
            menu.addItem("Оновити");
            menu.addItem("Назад");
            continue;
        }
        if (menu.getButton() == lilka::Button::C && !arpResults.empty() && cursor < (int)arpResults.size()) {
            // Парсимо IP і MAC з рядка
            String entry = arpResults[cursor];
            int sep = entry.indexOf(" - ");
            String ip = sep > 0 ? entry.substring(0, sep) : entry;
            String mac = sep > 0 ? entry.substring(sep + 3) : "";
            // Парсимо MAC у байти
            uint8_t macBytes[6] = {0};
            int mb = 0;
            int last = 0;
            for (int i = 0; i < (int)mac.length() && mb < 6; ++i) {
                if (mac[i] == ':' || mac[i] == '-') {
                    macBytes[mb++] = (uint8_t)strtol(mac.substring(last, i).c_str(), nullptr, 16);
                    last = i + 1;
                }
            }
            if (mb < 5) {
                // fallback: не вдалося розпарсити MAC
                macBytes[0] = macBytes[1] = macBytes[2] = 0;
            } else {
                macBytes[mb] = (uint8_t)strtol(mac.substring(last).c_str(), nullptr, 16);
            }
            const char* vendor = lookupVendor(macBytes);
            String info = "IP: " + ip + "\nMAC: " + mac;
            if (vendor && String(vendor) != "Unknown") {
                info += "\nVendor: ";
                info += vendor;
            }
            lilka::Alert alert("Device info", info);
            while (!alert.isFinished()) {
                alert.update();
                alert.draw(canvas);
                queueDraw();
            }
            continue;
        }
        // Якщо вибрано "No devices found" — просто оновити меню (нічого не робимо)
    }
}
 
// --- Додаємо структуру та масив OUI-вендорів ---
const MacVendor macVendors[] = VENDORS_LIST_INITIALIZER;
const int macVendorsCount = sizeof(macVendors) / sizeof(macVendors[0]);
 
// Функція для пошуку вендора за MAC
const char* lookupVendor(const uint8_t mac[6]) {
    uint32_t target = (mac[0] << 16) | (mac[1] << 8) | mac[2];
    int left = 0, right = macVendorsCount - 1;
    while (left <= right) {
        int mid = (left + right) / 2;
        uint32_t midOUI = (macVendors[mid].oui[0] << 16) | (macVendors[mid].oui[1] << 8) | macVendors[mid].oui[2];
        if (target == midOUI) return macVendors[mid].vendor;
        if (target < midOUI) right = mid - 1;
        else left = mid + 1;
    }
    return "Unknown";
}
