#include "vault.hpp"

#include <iostream>
#include <string>

using alfie::ChunkVault;

static int usage() {
    std::cerr << "Usage:\n"
              << "  alfie-vault put-account <vault-dir> <domain> <username> <passphrase> <json>\n"
              << "  alfie-vault get-account <vault-dir> <domain> <username> <passphrase>\n";
    return 2;
}

int main(int argc, char** argv) {
    if (argc < 2) return usage();
    std::string cmd = argv[1];
    try {
        if (cmd == "put-account") {
            if (argc != 7) return usage();
            ChunkVault vault(argv[2]);
            auto path = vault.put("account", argv[3], argv[4], argv[5], argv[6]);
            std::cout << "stored " << path << "\n";
            return 0;
        }
        if (cmd == "get-account") {
            if (argc != 6) return usage();
            ChunkVault vault(argv[2]);
            std::cout << vault.get("account", argv[3], argv[4], argv[5]) << "\n";
            return 0;
        }
        return usage();
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
