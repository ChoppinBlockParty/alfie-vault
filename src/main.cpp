#include <iostream>
#include <string>

#include "http_unlock.hpp"
#include "vault.hpp"

using alfie::ChunkVault;
using alfie::UnlockRequestSpec;
using alfie::UnlockService;

static int usage() {
  std::cerr << "Usage:\n"
            << "  alfie-vault put-account <vault-dir> <domain> <username> <passphrase> <json>\n"
            << "  alfie-vault get-account <vault-dir> <domain> <username> <passphrase>\n"
            << "  alfie-vault serve-unlock <vault-dir> <login> <host> <port> <purpose> <domain> "
               "<account> <action>\n"
            << "  alfie-vault serve-store <vault-dir> <login> <host> <port> <purpose> <domain> "
               "<account> <action>\n"
            << "  alfie-vault serve-unlock-tls <vault-dir> <login> <host> <port> <cert> <key> "
               "<purpose> <domain> <account> <action>\n"
            << "  alfie-vault serve-store-tls <vault-dir> <login> <host> <port> <cert> <key> "
               "<purpose> <domain> <account> <action>\n";
  return 2;
}

int main(int argc, char** argv) {
  if (argc < 2)
    return usage();
  std::string cmd = argv[1];
  try {
    if (cmd == "put-account") {
      if (argc != 7)
        return usage();
      ChunkVault vault(argv[2]);
      auto path = vault.put("account", argv[3], argv[4], argv[5], argv[6]);
      std::cout << "stored " << path << "\n";
      return 0;
    }
    if (cmd == "get-account") {
      if (argc != 6)
        return usage();
      ChunkVault vault(argv[2]);
      std::cout << vault.get("account", argv[3], argv[4], argv[5]) << "\n";
      return 0;
    }
    if (cmd == "serve-unlock") {
      if (argc != 10)
        return usage();
      UnlockService service(argv[2], argv[3]);
      UnlockRequestSpec spec{argv[6], argv[7], argv[8], argv[9]};
      auto token = service.create_token(spec);
      std::cout << "unlock link: http://" << argv[4] << ":" << argv[5] << "/unlock/" << token
                << "\n"
                << std::flush;
      return alfie::run_http_unlock_server(service, argv[4], std::stoi(argv[5]));
    }
    if (cmd == "serve-store") {
      if (argc != 10)
        return usage();
      UnlockService service(argv[2], argv[3]);
      UnlockRequestSpec spec{argv[6], argv[7], argv[8], argv[9]};
      auto token = service.create_store_token(spec);
      std::cout << "store link: http://" << argv[4] << ":" << argv[5] << "/store/" << token << "\n"
                << std::flush;
      return alfie::run_http_unlock_server(service, argv[4], std::stoi(argv[5]));
    }
    if (cmd == "serve-unlock-tls") {
      if (argc != 12)
        return usage();
      UnlockService service(argv[2], argv[3]);
      UnlockRequestSpec spec{argv[8], argv[9], argv[10], argv[11]};
      auto token = service.create_token(spec);
      std::cout << "unlock link: https://" << argv[4] << ":" << argv[5] << "/unlock/" << token
                << "\n"
                << std::flush;
      return alfie::run_https_unlock_server(service, argv[4], std::stoi(argv[5]), argv[6], argv[7]);
    }
    if (cmd == "serve-store-tls") {
      if (argc != 12)
        return usage();
      UnlockService service(argv[2], argv[3]);
      UnlockRequestSpec spec{argv[8], argv[9], argv[10], argv[11]};
      auto token = service.create_store_token(spec);
      std::cout << "store link: https://" << argv[4] << ":" << argv[5] << "/store/" << token << "\n"
                << std::flush;
      return alfie::run_https_unlock_server(service, argv[4], std::stoi(argv[5]), argv[6], argv[7]);
    }
    return usage();
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
