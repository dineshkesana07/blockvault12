#include "OtpEmail.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <cstdlib>
#include <iostream>
#include <regex>
#include <string>

namespace {
using json = nlohmann::json;

constexpr char kResendUrl[] = "https://api.resend.com/emails";
constexpr size_t kMaxResponseBytes = 64 * 1024;

struct ResendConfig {
  std::string apiKey;
  std::string fromEmail;

  ~ResendConfig() {
    if (!apiKey.empty()) {
      sodium_memzero(apiKey.data(), apiKey.size());
    }
  }
};

struct ResponseBuffer {
  std::string body;
  bool exceededLimit{false};
};

std::string getEnvironmentValue(const char *name) {
  const char *value = std::getenv(name);
  return value ? value : "";
}

bool isValidEmailAddress(const std::string &email) {
  if (email.empty() || email.size() > 254 ||
      email.find_first_of("\r\n") != std::string::npos ||
      email.find('\0') != std::string::npos) {
    return false;
  }
  static const std::regex emailPattern(
      R"(^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$)");
  return std::regex_match(email, emailPattern);
}

bool readConfig(ResendConfig &config) {
  config.apiKey = getEnvironmentValue("RESEND_API_KEY");
  config.fromEmail = getEnvironmentValue("OTP_FROM_EMAIL");
  if (config.apiKey.empty() || config.apiKey.find_first_of("\r\n") !=
                                   std::string::npos ||
      config.apiKey.find('\0') != std::string::npos ||
      !isValidEmailAddress(config.fromEmail)) {
    std::cerr << "[OTP email] Resend configuration is missing or invalid; "
                 "check RESEND_API_KEY and OTP_FROM_EMAIL. Values are not "
                 "logged."
              << std::endl;
    return false;
  }
  return true;
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

size_t receiveResponse(char *data, size_t size, size_t count, void *userData) {
  auto *response = static_cast<ResponseBuffer *>(userData);
  if (size != 0 && count > static_cast<size_t>(-1) / size) {
    response->exceededLimit = true;
    return 0;
  }
  const size_t bytes = size * count;
  if (bytes > kMaxResponseBytes - response->body.size()) {
    response->exceededLimit = true;
    return 0;
  }
  response->body.append(data, bytes);
  return bytes;
}

void wipeString(std::string &value) {
  if (!value.empty()) {
    sodium_memzero(value.data(), value.size());
    value.clear();
  }
}

const char *httpFailureCategory(long status) {
  switch (status) {
  case 400:
    return "Resend rejected the email request";
  case 401:
    return "Resend API key was rejected";
  case 403:
    return "Resend sender or account is not authorized";
  case 429:
    return "Resend rate limit was reached";
  default:
    return status >= 500 ? "Resend service error"
                         : "Resend returned an unexpected HTTP status";
  }
}
} // namespace

bool OtpEmail::isConfigured() {
  ResendConfig config;
  return readConfig(config);
}

bool OtpEmail::sendVerificationCode(const std::string &email,
                                    const std::string &name,
                                    const std::string &otp) {
  if (!isValidEmailAddress(email) || otp.size() != 6 ||
      otp.find_first_not_of("0123456789") != std::string::npos ||
      name.find_first_of("\r\n") != std::string::npos ||
      name.find('\0') != std::string::npos) {
    std::cerr << "[OTP email] Refusing to send due to invalid recipient or "
                 "message fields."
              << std::endl;
    return false;
  }

  ResendConfig config;
  if (!readConfig(config)) {
    return false;
  }

  static const bool curlInitialized =
      curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
  if (!curlInitialized) {
    std::cerr << "[OTP email] libcurl global initialization failed."
              << std::endl;
    return false;
  }

  const std::string safeName = escapeHtml(name);
  const std::string html =
      "<!doctype html><html><body style=\"margin:0;background:#080d1a;"
      "font-family:Arial,sans-serif;color:#f8fafc;padding:32px\">"
      "<div style=\"max-width:520px;margin:auto;background:#101827;"
      "border:1px solid #293449;border-radius:16px;padding:32px\">"
      "<p style=\"color:#22d3ee;font-weight:bold;letter-spacing:2px\">"
      "BLOCKVAULT</p><h1 style=\"font-size:24px\">Verify your email</h1>"
      "<p>Hello " +
      safeName +
      ",</p><p>Use this one-time code to finish creating your BlockVault "
      "account:</p><div style=\"background:#080d1a;border-radius:12px;"
      "padding:20px;text-align:center;font-size:32px;font-weight:bold;"
      "letter-spacing:10px;color:#a78bfa\">" +
      otp +
      "</div><p>This code expires in <strong>5 minutes</strong> and can only "
      "be used once.</p><p style=\"color:#fbbf24\"><strong>Security "
      "reminder:</strong> Never share this code with anyone. BlockVault will "
      "never ask you for it.</p><p style=\"color:#94a3b8;font-size:13px\">"
      "If you did not request this code, you can safely ignore this "
      "email.</p></div></body></html>";
  std::string text =
      "Hello " + name +
      ",\n\nUse this one-time code to finish creating your BlockVault "
      "account: " +
      otp +
      "\n\nThis code expires in 5 minutes and can only be used once. Never "
      "share this code with anyone.\n";
  std::string requestBody =
      json{{"from", config.fromEmail},
           {"to", json::array({email})},
           {"subject", "BlockVault Email Verification"},
           {"html", html},
           {"text", text}}
          .dump();
  wipeString(text);

  CURL *curl = curl_easy_init();
  if (!curl) {
    std::cerr << "[OTP email] Could not allocate a libcurl HTTP handle."
              << std::endl;
    wipeString(requestBody);
    return false;
  }

  curl_slist *headers = nullptr;
  const std::string authorization = "Authorization: Bearer " + config.apiKey;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  if (headers) {
    curl_slist *updated = curl_slist_append(headers, authorization.c_str());
    if (updated) {
      headers = updated;
    } else {
      curl_slist_free_all(headers);
      headers = nullptr;
    }
  }
  if (!headers) {
    std::cerr << "[OTP email] Could not allocate HTTP request headers."
              << std::endl;
    curl_easy_cleanup(curl);
    wipeString(requestBody);
    return false;
  }

  ResponseBuffer response;
  const auto setOption = [curl](CURLoption option, auto value) {
    return curl_easy_setopt(curl, option, value) == CURLE_OK;
  };
  const bool optionsSet =
      setOption(CURLOPT_URL, kResendUrl) &&
      setOption(CURLOPT_PROTOCOLS_STR, "https") &&
      setOption(CURLOPT_HTTPHEADER, headers) &&
      setOption(CURLOPT_POST, 1L) &&
      setOption(CURLOPT_POSTFIELDS, requestBody.data()) &&
      setOption(CURLOPT_POSTFIELDSIZE_LARGE,
                static_cast<curl_off_t>(requestBody.size())) &&
      setOption(CURLOPT_WRITEFUNCTION, receiveResponse) &&
      setOption(CURLOPT_WRITEDATA, &response) &&
      setOption(CURLOPT_SSL_VERIFYPEER, 1L) &&
      setOption(CURLOPT_SSL_VERIFYHOST, 2L) &&
      setOption(CURLOPT_CONNECTTIMEOUT, 10L) &&
      setOption(CURLOPT_TIMEOUT, 20L) &&
      setOption(CURLOPT_NOSIGNAL, 1L);

  CURLcode result = CURLE_OK;
  long status = 0;
  if (!optionsSet) {
    std::cerr << "[OTP email] Failed to configure a libcurl HTTP option."
              << std::endl;
    result = CURLE_FAILED_INIT;
  } else {
    result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  }
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  wipeString(requestBody);

  if (result != CURLE_OK) {
    std::cerr << "[OTP email] Resend HTTPS request failed (libcurl="
              << static_cast<int>(result)
              << (response.exceededLimit ? ", response too large"
                                         : ", no request details logged")
              << "). No credentials, addresses, message content, or OTP "
                 "values were logged."
              << std::endl;
    return false;
  }

  const json responseJson = json::parse(response.body, nullptr, false);
  const bool accepted = status >= 200 && status < 300 &&
                        responseJson.is_object() &&
                        responseJson.contains("id") &&
                        responseJson["id"].is_string() &&
                        !responseJson["id"].get_ref<const std::string &>().empty();
  if (!accepted) {
    std::cerr << "[OTP email] "
              << httpFailureCategory(status)
              << " (HTTP " << status
              << (responseJson.is_discarded() ? ", invalid JSON response"
                                              : ", request not accepted")
              << "). Response body and credentials were not logged."
              << std::endl;
    return false;
  }

  return true;
}
