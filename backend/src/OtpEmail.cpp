#include "OtpEmail.h"
#include <curl/curl.h>
#include <sodium.h>
#include <cstdlib>
#include <cstring>
#include <regex>
#include <string>

namespace {
bool isSafeHeaderValue(const std::string &value) {
  return !value.empty() && value.find_first_of("\r\n\0") == std::string::npos;
}

bool isValidSmtpRecipient(const std::string &email) {
  if (email.empty() || email.size() > 254) {
    return false;
  }
  if (email.find_first_of("\r\n\0") != std::string::npos) {
    return false;
  }
  static const std::regex emailPattern(
      R"(^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$)");
  return std::regex_match(email, emailPattern);
}

struct SmtpConfig {
  std::string host;
  std::string username;
  std::string password;
  std::string fromEmail;
  long port{0};

  ~SmtpConfig() {
    if (!password.empty()) {
      sodium_memzero(password.data(), password.size());
    }
  }
};

std::string getEnvironmentValue(const char *name) {
  const char *value = std::getenv(name);
  return value ? value : "";
}

bool readConfig(SmtpConfig &config) {
  config.host = getEnvironmentValue("SMTP_HOST");
  config.username = getEnvironmentValue("SMTP_USERNAME");
  config.password = getEnvironmentValue("SMTP_PASSWORD");
  config.fromEmail = getEnvironmentValue("SMTP_FROM_EMAIL");

  const std::string port = getEnvironmentValue("SMTP_PORT");
  if (config.host.empty() || config.username.empty() ||
      config.password.empty() || config.fromEmail.empty() || port.empty() ||
      !isSafeHeaderValue(config.host) ||
      !isSafeHeaderValue(config.username) ||
      !isSafeHeaderValue(config.password) ||
      !isSafeHeaderValue(config.fromEmail) ||
      config.host.find('/') != std::string::npos ||
      config.fromEmail.find_first_of("<>") != std::string::npos) {
    return false;
  }

  char *end = nullptr;
  config.port = std::strtol(port.c_str(), &end, 10);
  return end != port.c_str() && *end == '\0' &&
         config.port >= 1 && config.port <= 65535;
}

std::string escapeHtml(const std::string &value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (char character : value) {
    switch (character) {
    case '&':
      escaped += "&amp;";
      break;
    case '<':
      escaped += "&lt;";
      break;
    case '>':
      escaped += "&gt;";
      break;
    case '"':
      escaped += "&quot;";
      break;
    case '\'':
      escaped += "&#39;";
      break;
    default:
      escaped += character;
      break;
    }
  }
  return escaped;
}

void wipeMessage(std::string &message) {
  if (!message.empty()) {
    sodium_memzero(message.data(), message.size());
    message.clear();
  }
}

struct MessageReadContext {
 const std::string &message;
 size_t offset{0};
};

size_t readMessage(char *buffer, size_t size, size_t count, void *userData) {
 auto *context = static_cast<MessageReadContext *>(userData);
 const size_t capacity = size * count;
 const size_t remaining = context->message.size() - context->offset;
 const size_t bytes = remaining < capacity ? remaining : capacity;
 if (bytes > 0) {
   std::memcpy(buffer, context->message.data() + context->offset, bytes);
   context->offset += bytes;
 }
 return bytes;
}
} // namespace

bool OtpEmail::isConfigured() {
  SmtpConfig config;
  return readConfig(config);
}

bool OtpEmail::sendVerificationCode(const std::string &email,
                                    const std::string &name,
                                    const std::string &otp) {
  if (!isValidSmtpRecipient(email) || otp.empty() ||
      otp.find_first_not_of("0123456789") != std::string::npos ||
      name.find_first_of("\r\n\0") != std::string::npos) {
    return false;
  }

  SmtpConfig config;
  if (!readConfig(config)) {
    return false;
  }

  static const bool curlInitialized = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
  if (!curlInitialized) {
    return false;
  }

  std::string message =
      "To: " + email + "\r\n"
      "From: BlockVault <" + config.fromEmail + ">\r\n"
      "Subject: Verify your BlockVault email\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: text/html; charset=UTF-8\r\n"
      "Content-Transfer-Encoding: 8bit\r\n\r\n"
      "<!doctype html><html><body style=\"margin:0;background:#080d1a;"
      "font-family:Arial,sans-serif;color:#f8fafc;padding:32px\">"
      "<div style=\"max-width:520px;margin:auto;background:#101827;"
      "border:1px solid #293449;border-radius:16px;padding:32px\">"
      "<p style=\"color:#22d3ee;font-weight:bold;letter-spacing:2px\">"
      "BLOCKVAULT</p><h1 style=\"font-size:24px\">Verify your email</h1>"
      "<p>Hello " + escapeHtml(name) + ",</p>"
      "<p>Use this one-time code to finish creating your BlockVault account:</p>"
      "<div style=\"background:#080d1a;border-radius:12px;padding:20px;"
      "text-align:center;font-size:32px;font-weight:bold;letter-spacing:10px;"
      "color:#a78bfa\">" + otp + "</div>"
      "<p>This code expires in <strong>5 minutes</strong> and can only be used "
      "once.</p><p style=\"color:#fbbf24\"><strong>Security reminder:</strong> "
      "Never share this code with anyone. BlockVault will never ask you for it.</p>"
      "<p style=\"color:#94a3b8;font-size:13px\">If you did not request this "
      "code, you can safely ignore this email.</p></div></body></html>\r\n";

  CURL *curl = curl_easy_init();
  if (!curl) {
    wipeMessage(message);
    return false;
  }

  curl_slist *recipients = nullptr;
  recipients = curl_slist_append(recipients, ("<" + email + ">").c_str());
  if (!recipients) {
    curl_easy_cleanup(curl);
    wipeMessage(message);
    return false;
  }

  const std::string scheme = config.port == 465 ? "smtps://" : "smtp://";
  const std::string url =
      scheme + config.host + ":" + std::to_string(config.port);
  const std::string envelopeFrom = "<" + config.fromEmail + ">";
  MessageReadContext readContext{message};
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_USERNAME, config.username.c_str());
  curl_easy_setopt(curl, CURLOPT_PASSWORD, config.password.c_str());
  curl_easy_setopt(curl, CURLOPT_MAIL_FROM, envelopeFrom.c_str());
  curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
  if (config.port != 465) {
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
  }
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, readMessage);
  curl_easy_setopt(curl, CURLOPT_READDATA, &readContext);
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                   static_cast<curl_off_t>(message.size()));

  const CURLcode result = curl_easy_perform(curl);
  curl_slist_free_all(recipients);
  curl_easy_cleanup(curl);
  wipeMessage(message);
  return result == CURLE_OK;
}
