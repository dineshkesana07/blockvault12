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

constexpr size_t kMaxResponseBytes = 16 * 1024;
constexpr char kGoogleAppsScriptHost[] = "script.google.com";

struct EmailServiceConfig {
  std::string url;
  std::string token;

  ~EmailServiceConfig() {
    if (!token.empty()) {
      sodium_memzero(token.data(), token.size());
    }
  }
};

struct ResponseBuffer {
  std::string body;
  bool exceededLimit{false};
};

bool initializeCurl() {
  static const bool initialized =
      curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
  return initialized;
}

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

bool isGoogleAppsScriptUrl(const std::string &url) {
  CURLU *parsedUrl = curl_url();
  if (!parsedUrl) {
    return false;
  }

  const CURLUcode parseResult =
      curl_url_set(parsedUrl, CURLUPART_URL, url.c_str(), CURLU_DISALLOW_USER);
  char *scheme = nullptr;
  char *host = nullptr;
  char *path = nullptr;
  const bool valid =
      parseResult == CURLUE_OK &&
      curl_url_get(parsedUrl, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
      curl_url_get(parsedUrl, CURLUPART_HOST, &host, 0) == CURLUE_OK &&
      curl_url_get(parsedUrl, CURLUPART_PATH, &path, 0) == CURLUE_OK &&
      std::string(scheme) == "https" &&
      std::string(host) == kGoogleAppsScriptHost &&
      std::string(path).rfind("/macros/s/", 0) == 0 &&
      std::string(path).size() > std::string("/macros/s/").size() + 5 &&
      std::string(path).compare(std::string(path).size() - 5, 5, "/exec") ==
          0;
  curl_free(scheme);
  curl_free(host);
  curl_free(path);
  curl_url_cleanup(parsedUrl);
  return valid;
}

bool readConfig(EmailServiceConfig &config) {
  if (!initializeCurl()) {
    std::cerr << "[OTP email] libcurl global initialization failed."
              << std::endl;
    return false;
  }
  config.url = getEnvironmentValue("EMAIL_SERVICE_URL");
  config.token = getEnvironmentValue("EMAIL_SERVICE_TOKEN");
  if (config.token.empty() ||
      config.token.find_first_of("\r\n") != std::string::npos ||
      config.token.find('\0') != std::string::npos ||
      !isGoogleAppsScriptUrl(config.url)) {
    std::cerr << "[OTP email] Email service configuration is missing or "
                 "invalid; check EMAIL_SERVICE_URL and EMAIL_SERVICE_TOKEN. "
                 "Values are not logged."
              << std::endl;
    return false;
  }
  return true;
}

size_t receiveResponse(char *data, size_t size, size_t count, void *userData) {
  auto *response = static_cast<ResponseBuffer *>(userData);
  if (size != 0 && count > static_cast<size_t>(-1) / size) {
    response->exceededLimit = true;
    return 0;
  }
  const size_t bytes = size * count;
  if (response->body.size() > kMaxResponseBytes ||
      bytes > kMaxResponseBytes - response->body.size()) {
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
} // namespace

bool OtpEmail::isConfigured() {
  EmailServiceConfig config;
  return readConfig(config);
}

bool OtpEmail::sendVerificationCode(const std::string &email,
                                    const std::string &otp) {
  if (!isValidEmailAddress(email) || otp.size() != 6 ||
      otp.find_first_not_of("0123456789") != std::string::npos) {
    std::cerr << "[OTP email] Refusing to send due to invalid recipient or "
                 "verification code."
              << std::endl;
    return false;
  }

  EmailServiceConfig config;
  if (!readConfig(config)) {
    return false;
  }

  if (!initializeCurl()) {
    std::cerr << "[OTP email] libcurl global initialization failed."
              << std::endl;
    return false;
  }

  std::string requestBody =
      json{{"token", config.token}, {"email", email}, {"otp", otp}}.dump();
  CURL *curl = curl_easy_init();
  if (!curl) {
    std::cerr << "[OTP email] Could not allocate a libcurl HTTP handle."
              << std::endl;
    wipeString(requestBody);
    return false;
  }

  curl_slist *headers =
      curl_slist_append(nullptr, "Content-Type: application/json");
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
      setOption(CURLOPT_URL, config.url.c_str()) &&
      setOption(CURLOPT_PROTOCOLS_STR, "https") &&
      setOption(CURLOPT_REDIR_PROTOCOLS_STR, "https") &&
      setOption(CURLOPT_FOLLOWLOCATION, 1L) &&
      setOption(CURLOPT_MAXREDIRS, 5L) &&
      setOption(CURLOPT_POSTREDIR, static_cast<long>(CURL_REDIR_POST_ALL)) &&
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
      setOption(CURLOPT_TIMEOUT, 25L) &&
      setOption(CURLOPT_NOSIGNAL, 1L);

  CURLcode result = CURLE_OK;
  long status = 0;
  if (!optionsSet) {
    std::cerr << "[OTP email] Failed to configure an HTTPS request option."
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
    std::cerr << "[OTP email] Email service HTTPS request failed (libcurl="
              << static_cast<int>(result)
              << (response.exceededLimit ? ", response too large"
                                         : ", request details withheld")
              << "). No service token, email address, or OTP was logged."
              << std::endl;
    wipeString(response.body);
    return false;
  }

  const json responseJson = json::parse(response.body, nullptr, false);
  const bool accepted =
      status >= 200 && status < 300 && responseJson.is_object() &&
      responseJson.contains("success") &&
      responseJson["success"].is_boolean() &&
      responseJson["success"].get<bool>();
  wipeString(response.body);
  if (!accepted) {
    std::cerr << "[OTP email] Email service did not confirm delivery "
              << "(HTTP " << status << "). No response body or secret values "
                 "were logged."
              << std::endl;
    return false;
  }
  return true;
}
