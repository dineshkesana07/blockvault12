#include "Auth.h"
#include "Database.h"
#include <sodium.h>
#include <sqlite3.h>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

namespace {
void require(bool condition, const char *message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << std::endl;
    std::exit(1);
  }
}

std::string hashOtp(const std::string &email, const std::string &otp) {
  const std::string secret(32, 't');
  unsigned char key[crypto_generichash_KEYBYTES];
  unsigned char digest[crypto_generichash_BYTES];
  require(crypto_generichash(
              key, sizeof(key),
              reinterpret_cast<const unsigned char *>(secret.data()),
              secret.size(), nullptr, 0) == 0,
          "derive OTP test key");

  const std::string input = email + '\0' + otp;
  require(crypto_generichash(
              digest, sizeof(digest),
              reinterpret_cast<const unsigned char *>(input.data()),
              input.size(), key, sizeof(key)) == 0,
          "hash OTP test code");
  sodium_memzero(key, sizeof(key));

  static const char hex[] = "0123456789abcdef";
  std::string result;
  result.reserve(sizeof(digest) * 2);
  for (unsigned char byte : digest) {
    result.push_back(hex[byte >> 4]);
    result.push_back(hex[byte & 0x0f]);
  }
  sodium_memzero(digest, sizeof(digest));
  return result;
}

std::string makePasswordHash(const std::string &password) {
  char hash[crypto_pwhash_STRBYTES];
  require(crypto_pwhash_str(hash, password.c_str(), password.size(),
                            crypto_pwhash_OPSLIMIT_INTERACTIVE,
                            crypto_pwhash_MEMLIMIT_INTERACTIVE) == 0,
          "create Argon2id test password hash");
  std::string result(hash);
  sodium_memzero(hash, sizeof(hash));
  return result;
}

void configureOtpTestSecret() {
  const std::string secret(32, 't');
#if defined(_WIN32)
  require(_putenv_s("OTP_HASH_SECRET", secret.c_str()) == 0,
          "configure OTP test secret");
#else
  require(setenv("OTP_HASH_SECRET", secret.c_str(), 1) == 0,
          "configure OTP test secret");
#endif
}

void checkOtpIsHashed(const std::filesystem::path &path,
                      const std::string &email, const std::string &otp) {
  sqlite3 *database = nullptr;
  require(sqlite3_open(path.string().c_str(), &database) == SQLITE_OK,
          "open test database for OTP storage check");

  sqlite3_stmt *statement = nullptr;
  require(sqlite3_prepare_v2(
              database, "SELECT otp_hash FROM pending_signups WHERE email = ?;",
              -1, &statement, nullptr) == SQLITE_OK,
          "prepare OTP storage check");
  sqlite3_bind_text(statement, 1, email.c_str(), -1, SQLITE_TRANSIENT);
  require(sqlite3_step(statement) == SQLITE_ROW, "find pending OTP");
  const auto *stored = reinterpret_cast<const char *>(
      sqlite3_column_text(statement, 0));
  require(stored != nullptr && std::string(stored) != otp,
          "OTP is not stored in plaintext");
  require(stored != nullptr && std::string(stored).size() == 64,
          "OTP is stored as a keyed digest");
  sqlite3_finalize(statement);
  sqlite3_close(database);
}
} // namespace

int main() {
  require(sodium_init() >= 0, "initialize libsodium");

  const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto path = std::filesystem::temp_directory_path() /
      ("blockvault-otp-test-" + std::to_string(suffix) + ".db");
  const int64_t now = 2000000000;
  const std::string password = "StrongTestPassword9!";
  const std::string passwordHash = makePasswordHash(password);
  const std::string salt(32, 'a');

  {
    Database database(path.string());
    require(database.init(), "initialize migrated SQLite schema");

    const std::string email = "otp-flow@example.com";
    const std::string firstOtp = "012345";
    require(database.createPendingSignup(
                "OTP Test", email, passwordHash, salt, hashOtp(email, firstOtp),
                now + 300, now) == PendingSignupCreateStatus::Created,
            "create pending signup");
    checkOtpIsHashed(path, email, firstOtp);
    require(database.verifyPendingSignupOtp(
                email, hashOtp(email, firstOtp), now + 1, password).status ==
                OtpVerificationStatus::Invalid,
            "reject an OTP before email delivery is confirmed");
    require(!database.isPendingSignupOtpDeliveryConfirmed(email),
            "report pending OTP as undelivered");
    require(database.confirmPendingSignupOtpDelivery(email,
                                                     hashOtp(email, firstOtp)),
            "confirm OTP delivery");
    require(database.isPendingSignupOtpDeliveryConfirmed(email),
            "report OTP as delivered after confirmation");

    for (int attempt = 0; attempt < 4; ++attempt) {
      require(database.verifyPendingSignupOtp(
                  email, hashOtp(email, "999999"), now + 1, password).status ==
                  OtpVerificationStatus::Invalid,
              "reject an incorrect OTP");
    }
    require(database.verifyPendingSignupOtp(
                email, hashOtp(email, "999999"), now + 1, password).status ==
                OtpVerificationStatus::TooManyAttempts,
            "enforce five failed attempts");

    const std::string secondOtp = "654321";
    require(database.refreshPendingSignupOtp(
                email, hashOtp(email, secondOtp), now + 360, now + 59) ==
                OtpResendStatus::Cooldown,
            "enforce the 60-second resend cooldown");
    require(database.refreshPendingSignupOtp(
                email, hashOtp(email, secondOtp), now + 360, now + 60) ==
                OtpResendStatus::Updated,
            "resend after cooldown and rotate the previous OTP");
    require(database.verifyPendingSignupOtp(
                email, hashOtp(email, secondOtp), now + 61, password).status ==
                OtpVerificationStatus::Invalid,
            "reject a resent OTP until its email delivery is confirmed");
    require(database.confirmPendingSignupOtpDelivery(email,
                                                     hashOtp(email, secondOtp)),
            "confirm resent OTP delivery");
    require(!database.confirmPendingSignupOtpDelivery(
                email, hashOtp(email, firstOtp)),
            "do not confirm a stale OTP after resend");
    require(database.verifyPendingSignupOtp(
                email, hashOtp(email, firstOtp), now + 61, password).status ==
                OtpVerificationStatus::Invalid,
            "reject the replaced OTP");
    require(database.verifyPendingSignupOtp(
                email, hashOtp(email, secondOtp), now + 62,
                "WrongPassword9!").status == OtpVerificationStatus::Invalid,
            "require the password associated with the pending signup");
    require(database.verifyPendingSignupOtp(
                email, hashOtp(email, secondOtp), now + 63, password).status ==
                OtpVerificationStatus::Verified,
            "create a user after valid OTP and password verification");
    require(database.getUserByEmail(email).has_value(),
            "persist the verified user");
    require(database.verifyPendingSignupOtp(
                email, hashOtp(email, secondOtp), now + 64, password).status ==
                OtpVerificationStatus::Invalid,
            "prevent OTP reuse");
    require(database.createPendingSignup(
                "OTP Test", email, passwordHash, salt, hashOtp(email, firstOtp),
                now + 300, now + 65) ==
                PendingSignupCreateStatus::AlreadyRegistered,
            "reject duplicate registrations without altering the existing user");

    const std::string expiredEmail = "expired@example.com";
    require(database.createPendingSignup(
                "Expired Test", expiredEmail, passwordHash, salt,
                hashOtp(expiredEmail, firstOtp), now + 300, now) ==
                PendingSignupCreateStatus::Created,
            "create expiring signup");
    require(database.confirmPendingSignupOtpDelivery(
                expiredEmail, hashOtp(expiredEmail, firstOtp)),
            "confirm expiring OTP delivery");
    require(database.verifyPendingSignupOtp(
                expiredEmail, hashOtp(expiredEmail, firstOtp), now + 300,
                password).status == OtpVerificationStatus::Expired,
            "reject an expired OTP");

    const std::string limitedEmail = "rate-limit@example.com";
    require(database.createPendingSignup(
                "Rate Test", limitedEmail, passwordHash, salt,
                hashOtp(limitedEmail, firstOtp), now + 300, now) ==
                PendingSignupCreateStatus::Created,
            "create rate-limited signup");
    for (int resend = 1; resend < 5; ++resend) {
      const int64_t resendAt = now + resend * 60;
      require(database.refreshPendingSignupOtp(
                  limitedEmail, hashOtp(limitedEmail, secondOtp), resendAt + 300,
                  resendAt) == OtpResendStatus::Updated,
              "allow resend within the hourly limit");
    }
    require(database.refreshPendingSignupOtp(
                limitedEmail, hashOtp(limitedEmail, secondOtp), now + 600,
                now + 300) == OtpResendStatus::RateLimited,
            "enforce the hourly send limit");

    configureOtpTestSecret();
    const std::string authEmail = "auth-flow@example.com";
    require(database.createPendingSignup(
                "Auth Test", authEmail, passwordHash, salt,
                hashOtp(authEmail, firstOtp), now + 300, now) ==
                PendingSignupCreateStatus::Created,
            "create signup for auth service verification");
    require(database.confirmPendingSignupOtpDelivery(
                authEmail, hashOtp(authEmail, firstOtp)),
            "confirm auth service OTP delivery");
    auto authDatabase = std::make_shared<Database>(path.string());
    require(authDatabase->init(), "open database for auth service verification");
    Auth auth(authDatabase);
    const OtpFlowResult verified =
        auth.verifyRegistrationOtp(authEmail, firstOtp, password);
    require(verified.status == OtpFlowStatus::Accepted &&
                verified.auth.success && auth.validateToken(verified.auth.token).has_value(),
            "complete signup and create a session after OTP verification");
    require(auth.verifyRegistrationOtp(authEmail, firstOtp, password).status ==
                OtpFlowStatus::Invalid,
            "prevent OTP reuse through the auth service");
    const AuthResult login = auth.loginUser(authEmail, password);
    require(login.success && auth.validateToken(login.token).has_value(),
            "allow login for a newly verified account");
    require(auth.logoutUser(login.token), "revoke an authenticated session");
  }

  std::error_code removeError;
  std::filesystem::remove(path, removeError);
  std::filesystem::remove(path.string() + "-wal", removeError);
  std::filesystem::remove(path.string() + "-shm", removeError);
  require(!removeError, "remove temporary SQLite test files");
  std::cout << "OTP database flow checks passed." << std::endl;
  return 0;
}
