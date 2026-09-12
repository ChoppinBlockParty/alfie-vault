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

static bool envFlag(const char *Name) {
  const char *Value = std::getenv(Name);
  return Value != nullptr && std::string(Value) == "1";
}

// Reads one line from stdin into secure memory. Echo is disabled when stdin is
// a terminal. The bytes never pass through a std::string, so no plaintext copy
// is left on the normal heap.
static SecureBuffer readSecretLine(const char *Prompt) {
  const bool Tty = isatty(STDIN_FILENO) != 0;
  termios Saved{};
  bool EchoDisabled = false;
  if (Tty) {
    std::cerr << Prompt << std::flush;
    if (tcgetattr(STDIN_FILENO, &Saved) == 0) {
      termios Quiet = Saved;
      Quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
      EchoDisabled = tcsetattr(STDIN_FILENO, TCSAFLUSH, &Quiet) == 0;
    }
  }

  SecureBytes Bytes;
  char C = 0;
  while (std::cin.get(C)) {
    if (C == '\n')
      break;
    Bytes.push_back(static_cast<unsigned char>(C));
  }
  if (!Bytes.empty() && Bytes.back() == '\r')
    Bytes.pop_back();

  if (EchoDisabled) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &Saved);
    std::cerr << "\n";
  }
  return SecureBuffer(std::move(Bytes));
}

// Reads the remainder of stdin into secure memory.
static SecureBuffer readSecretRest() {
  SecureBytes Bytes;
  char C = 0;
  while (std::cin.get(C))
    Bytes.push_back(static_cast<unsigned char>(C));
  while (!Bytes.empty() && (Bytes.back() == '\n' || Bytes.back() == '\r'))
    Bytes.pop_back();
  return SecureBuffer(std::move(Bytes));
}

int main(int Argc, char **Argv) {
  if (Argc < 2)
    return usage();
  try {
    std::string Cmd = Argv[1];
    // Before any secret is read: lock the secure heap in place and make core
    // dumps impossible.
    alfie::initProcessMemoryProtections(envFlag("ALFIE_VAULT_STRICT_MEMORY")
                                            ? alfie::MemoryPolicy::Strict
                                            : alfie::MemoryPolicy::BestEffort);

    if (Cmd == "init-vault") {
      if (Argc != 4)
        return usage();
      SecureBuffer Passphrase = readSecretLine("New master password: ");
      alfie::initVault(Argv[2], Argv[3], Passphrase);
      std::cout << "vault initialized " << Argv[2] << "\n";
      return 0;
    }
    if (Cmd == "put-account") {
      if (Argc != 5)
        return usage();
      SecureBuffer Passphrase = readSecretLine("Master password: ");
      SecureBuffer Payload = readSecretRest();
      ChunkVault Vault(Argv[2]);
      auto Path = Vault.put("account", Argv[3], Argv[4], Passphrase, Payload);
      std::cout << "stored " << Path << "\n";
      return 0;
    }
    if (Cmd == "get-account") {
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
      SecureBuffer Passphrase = readSecretLine("Master password: ");
      ChunkVault Vault(Argv[2]);
      Vault.use("account", Argv[3], Argv[4], Passphrase,
                [](const SecureBuffer &Secret) {
                  std::cout.write(reinterpret_cast<const char *>(Secret.data()),
                                  static_cast<std::streamsize>(Secret.size()));
                  std::cout << "\n";
                });
      return 0;
    }
    if (Cmd == "serve-init-tls") {
      if (Argc != 7)
        return usage();
      const std::filesystem::path VaultDir = Argv[2];
      const std::string ServerIp = Argv[3];
      const std::string BindHost = Argv[4];
      const int Port = std::stoi(Argv[5]);
      const std::filesystem::path OutputDir = Argv[6];

      // Refuse to even start against a live vault. The setup page must be
      // unreachable whenever a vault exists, not merely fail once someone has
      // typed a password into it.
      if (alfie::vaultInitialized(VaultDir)) {
        std::cerr
            << "error: vault already initialized at " << VaultDir << "\n"
            << "First-time setup can only run once. Nothing was served.\n";
        return 1;
      }

      // One-off certificate: generated in memory, never written to disk,
      // discarded on exit.
      alfie::GeneratedCertificate Ephemeral =
          alfie::generateEphemeralCertificate(BindHost);
      const std::string Fingerprint =
          alfie::certificateFingerprintSha256(Ephemeral.CertificatePem);

      UnlockService Service(VaultDir, "");
      Service.setTransportFingerprint(Fingerprint);
      alfie::InitPlan Plan;
      Plan.OutputDir = OutputDir;
      Plan.ServerIp = ServerIp;
      UnlockRequestSpec Spec{"init", "", "", "init_vault"};
      auto Token = Service.createInitToken(Spec, Plan);

      // The setup secret goes only to the trusted terminal, never into the link
      // or page.
      std::cout << "  One-time setup code: ";
      const auto &SetupCode = Service.setupCode(Token);
      std::cout.write(reinterpret_cast<const char *>(SetupCode.data()),
                      SetupCode.size());
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
          << "  Request code: " << Service.requestCode(Token) << "\n"
          << "  SHA-256: " << Fingerprint << "\n"
          << "\n"
          << "The setup page shows the same value. If they differ, you are\n"
          << "not talking to this server - close the page.\n"
          << "\n"
          << "setup link: https://" << BindHost << ":" << Port << "/init/"
          << Token << "\n"
          << "\n"
          << std::flush;

      return alfie::runHttpsUnlockServerInMemory(Service, BindHost, Port,
                                                 Ephemeral.CertificatePem,
                                                 Ephemeral.PrivateKeyPem);
    }
    if (Cmd == "serve-unlock-tls") {
      if (Argc != 12)
        return usage();
      UnlockService Service(Argv[2], Argv[3]);
      UnlockRequestSpec Spec{Argv[8], Argv[9], Argv[10], Argv[11]};
      auto Token = Service.createToken(Spec);
      std::cout << "unlock link: https://" << Argv[4] << ":" << Argv[5]
                << "/unlock/" << Token
                << "\nRequest code: " << Service.requestCode(Token) << "\n"
                << std::flush;
      return alfie::runHttpsUnlockServer(Service, Argv[4], std::stoi(Argv[5]),
                                         Argv[6], Argv[7]);
    }
    if (Cmd == "serve-store-tls") {
      if (Argc != 12)
        return usage();
      UnlockService Service(Argv[2], Argv[3]);
      UnlockRequestSpec Spec{Argv[8], Argv[9], Argv[10], Argv[11]};
      auto Token = Service.createStoreToken(Spec);
      std::cout << "store link: https://" << Argv[4] << ":" << Argv[5]
                << "/store/" << Token << "\n"
                << "Request code: " << Service.requestCode(Token) << "\n"
                << std::flush;
      return alfie::runHttpsUnlockServer(Service, Argv[4], std::stoi(Argv[5]),
                                         Argv[6], Argv[7]);
    }
    return usage();
  } catch (const std::exception &E) {
    std::cerr << "error: " << E.what() << "\n";
    return 1;
  }
}
