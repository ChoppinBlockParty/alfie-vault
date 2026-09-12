//===----------------------------------------------------------------------===//
/// \file
/// Expose vault setup and human-authorized HTTPS operations through the CLI.
//===----------------------------------------------------------------------===//

#include "ca.h"
#include "http_unlock.h"
#include "secure_memory.h"
#include "vault.h"
#include <cstdlib>
#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>

using alfie::ChunkVault;
using alfie::SecureBuffer;
using alfie::SecureBytes;
using alfie::UnlockRequestSpec;
using alfie::UnlockService;

static int usage() {
  std::cerr << "Usage:\n"
            << "  alfie-vault init-vault <vault-dir> <login>\n"
            << "  alfie-vault put-account <vault-dir> <domain> <username>\n"
            << "  alfie-vault get-account <vault-dir> <domain> <username>\n"
            << "  alfie-vault serve-init-tls <vault-dir> <server-ip> <host> "
               "<port> <output-dir>\n"
            << "  alfie-vault serve-unlock-tls <vault-dir> <login> <host> "
               "<port> <cert> <key> "
               "<purpose> <domain> <account> <action>\n"
            << "  alfie-vault serve-store-tls <vault-dir> <login> <host> "
               "<port> <cert> <key> "
               "<purpose> <domain> <account> <action>\n"
            << "\n"
            << "Secrets are read from stdin, never from argv: argv is visible "
               "process-wide via\n"
            << "/proc and ps. init-vault and put-account read the master "
               "password as the first line\n"
            << "of stdin; put-account reads the record payload from the rest.\n"
            << "\n"
            << "Environment:\n"
            << "  ALFIE_VAULT_STRICT_MEMORY=1          fail closed if secret "
               "memory cannot be\n"
            << "                                       locked or core dumps "
               "cannot be disabled\n"
            << "  ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1 required by "
               "get-account, which prints a\n"
            << "                                       decrypted record (test "
               "fixtures only)\n";
  return 2;
}

static bool envFlag(const char *name) {
  const char *value = std::getenv(name);
  return value != nullptr && std::string(value) == "1";
}

// Reads one line from stdin into secure memory. Echo is disabled when stdin is
// a terminal. The bytes never pass through a std::string, so no plaintext copy
// is left on the normal heap.
static SecureBuffer readSecretLine(const char *prompt) {
  const bool tty = isatty(STDIN_FILENO) != 0;
  termios saved{};
  bool echoDisabled = false;
  if (tty) {
    std::cerr << prompt << std::flush;
    if (tcgetattr(STDIN_FILENO, &saved) == 0) {
      termios quiet = saved;
      quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
      echoDisabled = tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0;
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

  if (echoDisabled) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
    std::cerr << "\n";
  }
  return SecureBuffer(std::move(bytes));
}

// Reads the remainder of stdin into secure memory.
static SecureBuffer readSecretRest() {
  SecureBytes bytes;
  char c = 0;
  while (std::cin.get(c))
    bytes.push_back(static_cast<unsigned char>(c));
  while (!bytes.empty() && (bytes.back() == '\n' || bytes.back() == '\r'))
    bytes.pop_back();
  return SecureBuffer(std::move(bytes));
}

int main(int Argc, char **Argv) {
  if (Argc < 2)
    return usage();
  try {
    std::string cmd = Argv[1];
    // Before any secret is read: lock the secure heap in place and make core
    // dumps impossible.
    alfie::initProcessMemoryProtections(envFlag("ALFIE_VAULT_STRICT_MEMORY")
                                            ? alfie::MemoryPolicy::Strict
                                            : alfie::MemoryPolicy::BestEffort);

    if (cmd == "init-vault") {
      if (Argc != 4)
        return usage();
      SecureBuffer passphrase = readSecretLine("New master password: ");
      alfie::initVault(Argv[2], Argv[3], passphrase);
      std::cout << "vault initialized " << Argv[2] << "\n";
      return 0;
    }
    if (cmd == "put-account") {
      if (Argc != 5)
        return usage();
      SecureBuffer passphrase = readSecretLine("Master password: ");
      SecureBuffer payload = readSecretRest();
      ChunkVault vault(Argv[2]);
      auto path = vault.put("account", Argv[3], Argv[4], passphrase, payload);
      std::cout << "stored " << path << "\n";
      return 0;
    }
    if (cmd == "get-account") {
      if (Argc != 5)
        return usage();
      // Printing a decrypted record to stdout is a test fixture, not a delivery
      // path: stdout lands in scrollback, pipes and logs. The production path
      // is the HTTPS unlock server.
      if (!envFlag("ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT")) {
        std::cerr << "error: get-account prints a decrypted record and is for "
                     "test fixtures "
                     "only.\nSet ALFIE_VAULT_ALLOW_PLAINTEXT_STDOUT=1 to "
                     "confirm, or use "
                     "serve-unlock-tls.\n";
        return 2;
      }
      SecureBuffer passphrase = readSecretLine("Master password: ");
      ChunkVault vault(Argv[2]);
      vault.use("account", Argv[3], Argv[4], passphrase,
                [](const SecureBuffer &secret) {
                  std::cout.write(reinterpret_cast<const char *>(secret.data()),
                                  static_cast<std::streamsize>(secret.size()));
                  std::cout << "\n";
                });
      return 0;
    }
    if (cmd == "serve-init-tls") {
      if (Argc != 7)
        return usage();
      const std::filesystem::path vaultDir = Argv[2];
      const std::string serverIp = Argv[3];
      const std::string bindHost = Argv[4];
      const int port = std::stoi(Argv[5]);
      const std::filesystem::path outputDir = Argv[6];

      // Refuse to even start against a live vault. The setup page must be
      // unreachable whenever a vault exists, not merely fail once someone has
      // typed a password into it.
      if (alfie::vaultInitialized(vaultDir)) {
        std::cerr
            << "error: vault already initialized at " << vaultDir << "\n"
            << "First-time setup can only run once. Nothing was served.\n";
        return 1;
      }

      // One-off certificate: generated in memory, never written to disk,
      // discarded on exit.
      alfie::GeneratedCertificate ephemeral =
          alfie::generateEphemeralCertificate(bindHost);
      const std::string fingerprint =
          alfie::certificateFingerprintSha256(ephemeral.certificatePem);

      UnlockService service(vaultDir, "");
      service.setTransportFingerprint(fingerprint);
      alfie::InitPlan plan;
      plan.outputDir = outputDir;
      plan.serverIp = serverIp;
      UnlockRequestSpec spec{"init", "", "", "init_vault"};
      auto token = service.createInitToken(spec, plan);

      // The setup secret goes only to the trusted terminal, never into the link
      // or page.
      std::cout << "  One-time setup code: ";
      const auto &setupCode = service.setupCode(token);
      std::cout.write(reinterpret_cast<const char *>(setupCode.data()),
                      setupCode.size());
      std::cout << "\n";

      std::cout
          << "\n"
          << "==========================================================\n"
          << "  FIRST-TIME VAULT SETUP - this runs exactly once\n"
          << "==========================================================\n"
          << "\n"
          << "Your browser will warn that this certificate is untrusted.\n"
          << "That is expected: no CA exists yet. Before typing anything,\n"
          << "check that the browser shows this exact fingerprint.\n"
          << "\n"
          << "  Request code: " << service.requestCode(token) << "\n"
          << "  SHA-256: " << fingerprint << "\n"
          << "\n"
          << "The setup page shows the same value. If they differ, you are\n"
          << "not talking to this server - close the page.\n"
          << "\n"
          << "setup link: https://" << bindHost << ":" << port << "/init/"
          << token << "\n"
          << "\n"
          << std::flush;

      return alfie::runHttpsUnlockServerInMemory(service, bindHost, port,
                                                 ephemeral.certificatePem,
                                                 ephemeral.privateKeyPem);
    }
    if (cmd == "serve-unlock-tls") {
      if (Argc != 12)
        return usage();
      UnlockService service(Argv[2], Argv[3]);
      UnlockRequestSpec spec{Argv[8], Argv[9], Argv[10], Argv[11]};
      auto token = service.createToken(spec);
      std::cout << "unlock link: https://" << Argv[4] << ":" << Argv[5]
                << "/unlock/" << token
                << "\nRequest code: " << service.requestCode(token) << "\n"
                << std::flush;
      return alfie::runHttpsUnlockServer(service, Argv[4], std::stoi(Argv[5]),
                                         Argv[6], Argv[7]);
    }
    if (cmd == "serve-store-tls") {
      if (Argc != 12)
        return usage();
      UnlockService service(Argv[2], Argv[3]);
      UnlockRequestSpec spec{Argv[8], Argv[9], Argv[10], Argv[11]};
      auto token = service.createStoreToken(spec);
      std::cout << "store link: https://" << Argv[4] << ":" << Argv[5]
                << "/store/" << token << "\n"
                << "Request code: " << service.requestCode(token) << "\n"
                << std::flush;
      return alfie::runHttpsUnlockServer(service, Argv[4], std::stoi(Argv[5]),
                                         Argv[6], Argv[7]);
    }
    return usage();
  } catch (const std::exception &e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
