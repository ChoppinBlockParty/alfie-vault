#include <termios.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>

#include "http_unlock.hpp"
#include "secure_memory.hpp"
#include "vault.hpp"

using alfie::ChunkVault;
using alfie::SecureBuffer;
using alfie::SecureBytes;
using alfie::UnlockRequestSpec;
using alfie::UnlockService;

namespace {

int usage() {
  std::cerr
      << "Usage:\n"
      << "  alfie-vault init-vault <vault-dir> <login>\n"
      << "  alfie-vault put-account <vault-dir> <domain> <username>\n"
      << "  alfie-vault get-account <vault-dir> <domain> <username>\n"
      << "  alfie-vault serve-init-tls <vault-dir> <login-hint> <host> <port> <cert> <key>\n"
      << "  alfie-vault serve-unlock-tls <vault-dir> <login> <host> <port> <cert> <key> "
         "<purpose> <domain> <account> <action>\n"
      << "  alfie-vault serve-store-tls <vault-dir> <login> <host> <port> <cert> <key> "
         "<purpose> <domain> <account> <action>\n"
      << "  alfie-vault serve-store-file-tls <vault-dir> <login> <host> <port> <cert> "
         "<key> <purpose> <domain> <account> <action> <source-file>\n"
      << "\n"
      << "Secrets are read from stdin, never from argv: argv is visible process-wide via\n"
      << "/proc and ps. init-vault and put-account read the master password as the first line\n"
      << "of stdin; put-account reads the record payload from the rest.\n"
      << "\n"
      << "Environment:\n"
      << "  ALFIE_VAULT_STRICT_MEMORY=1          fail closed if secret memory cannot be\n"
      << "                                       locked or core dumps cannot be disabled\n"
      << "  ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1 required by get-account, which prints a\n"
      << "                                       decrypted record (test fixtures only)\n";
  return 2;
}

bool env_flag(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && std::string(value) == "1";
}

// Reads one line from stdin into secure memory. Echo is disabled when stdin is a terminal.
// The bytes never pass through a std::string, so no plaintext copy is left on the normal heap.
SecureBuffer read_secret_line(const char* prompt) {
  const bool tty = isatty(STDIN_FILENO) != 0;
  termios saved{};
  bool echo_disabled = false;
  if (tty) {
    std::cerr << prompt << std::flush;
    if (tcgetattr(STDIN_FILENO, &saved) == 0) {
      termios quiet = saved;
      quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
      echo_disabled = tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0;
    }
  }

  SecureBytes bytes;
  char c = 0;
  while (std::cin.get(c)) {
    if (c == '\n')
      break;
    bytes.push_back(static_cast<unsigned char>(c));
  }
  if (!bytes.empty() && bytes.back() == '\r')
    bytes.pop_back();

  if (echo_disabled) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
    std::cerr << "\n";
  }
  return SecureBuffer(std::move(bytes));
}

// Reads the remainder of stdin into secure memory.
SecureBuffer read_secret_rest() {
  SecureBytes bytes;
  char c = 0;
  while (std::cin.get(c))
    bytes.push_back(static_cast<unsigned char>(c));
  while (!bytes.empty() && (bytes.back() == '\n' || bytes.back() == '\r'))
    bytes.pop_back();
  return SecureBuffer(std::move(bytes));
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2)
    return usage();
  std::string cmd = argv[1];
  try {
    // Before any secret is read: lock the secure heap in place and make core dumps impossible.
    alfie::init_process_memory_protections(env_flag("ALFIE_VAULT_STRICT_MEMORY")
                                               ? alfie::MemoryPolicy::Strict
                                               : alfie::MemoryPolicy::BestEffort);

    if (cmd == "init-vault") {
      if (argc != 4)
        return usage();
      SecureBuffer passphrase = read_secret_line("New master password: ");
      alfie::init_vault(argv[2], argv[3], passphrase);
      std::cout << "vault initialized " << argv[2] << "\n";
      return 0;
    }
    if (cmd == "put-account") {
      if (argc != 5)
        return usage();
      SecureBuffer passphrase = read_secret_line("Master password: ");
      SecureBuffer payload = read_secret_rest();
      ChunkVault vault(argv[2]);
      auto path = vault.put("account", argv[3], argv[4], passphrase, payload);
      std::cout << "stored " << path << "\n";
      return 0;
    }
    if (cmd == "get-account") {
      if (argc != 5)
        return usage();
      // Printing a decrypted record to stdout is a test fixture, not a delivery path: stdout
      // lands in scrollback, pipes and logs. The production path is the HTTPS unlock server.
      if (!env_flag("ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT")) {
        std::cerr << "error: get-account prints a decrypted record and is for test fixtures "
                     "only.\nSet ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1 to confirm, or use "
                     "serve-unlock-tls.\n";
        return 2;
      }
      SecureBuffer passphrase = read_secret_line("Master password: ");
      ChunkVault vault(argv[2]);
      vault.use("account", argv[3], argv[4], passphrase, [](const SecureBuffer& secret) {
        std::cout.write(reinterpret_cast<const char*>(secret.data()),
                        static_cast<std::streamsize>(secret.size()));
        std::cout << "\n";
      });
      return 0;
    }
    if (cmd == "serve-init-tls") {
      if (argc != 8)
        return usage();
      UnlockService service(argv[2], argv[3]);
      UnlockRequestSpec spec{"init", "", "", "init_vault"};
      auto token = service.create_init_token(spec);
      std::cout << "vault setup link: https://" << argv[4] << ":" << argv[5] << "/init/" << token
                << "\n"
                << std::flush;
      return alfie::run_https_unlock_server(service, argv[4], std::stoi(argv[5]), argv[6], argv[7]);
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
    if (cmd == "serve-store-file-tls") {
      if (argc != 13)
        return usage();
      UnlockService service(argv[2], argv[3]);
      UnlockRequestSpec spec{argv[8], argv[9], argv[10], argv[11]};
      auto token = service.create_store_file_token(spec, argv[12]);
      std::cout << "store file link: https://" << argv[4] << ":" << argv[5] << "/store-file/"
                << token << "\n"
                << std::flush;
      return alfie::run_https_unlock_server(service, argv[4], std::stoi(argv[5]), argv[6], argv[7]);
    }
    return usage();
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
