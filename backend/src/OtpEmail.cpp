#include "OtpEmail.h"
#include <curl/curl.h>
#include <sodium.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <regex>
#include <string>
#include <string_view>

namespace {
enum class SmtpPhase {
  Connection,
  StartTls,
  Authentication,
  Sender,
  Recipient,
  MessageData,
  Delivery,
  Other
};

struct SmtpDebugContext {
  SmtpPhase phase{SmtpPhase::Connection};
  long responseCode{0};
};

bool isSafeHeaderValue(const std::string &value) {
  return !value.empty() && value.find_first_of("\r\n") == std::string::npos &&
         value.find('\0') == std::string::npos;
}

bool isValidSmtpRecipient(const std::string &email) {
  if (email.empty() || email.size() > 254) {
    return false;
  }
  if (email.find_first_of("\r\n") != std::string::npos ||
      email.find('\0') != std::string::npos) {
    return false;
  }
  static const std::regex emailPattern(
      R"(^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$)");
  return std::regex_match(email, emailPattern);
}

size_t smtpDebugCallback(CURL *, curl_infotype type, char *data, size_t size,
                         void *userData) {
  auto *context = static_cast<SmtpDebugContext *>(userData);
  if (type == CURLINFO_HEADER_OUT) {
    const std::string_view command(data, size);
    if (command.rfind("STARTTLS", 0) == 0) {
      context->phase = SmtpPhase::StartTls;
    } else if (command.rfind("AUTH", 0) == 0) {
      context->phase = SmtpPhase::Authentication;
    } else if (command.rfind("MAIL FROM:", 0) == 0) {
      context->phase = SmtpPhase::Sender;
    } else if (command.rfind("RCPT TO:", 0) == 0) {
      context->phase = SmtpPhase::Recipient;
    } else if (command.rfind("DATA", 0) == 0) {
      context->phase = SmtpPhase::MessageData;
    }
  } else if (type == CURLINFO_HEADER_IN && size >= 3 &&
             data[0] >= '0' && data[0] <= '9' &&
             data[1] >= '0' && data[1] <= '9' &&
             data[2] >= '0' && data[2] <= '9') {
    context->responseCode =
        (data[0] - '0') * 100 + (data[1] - '0') * 10 + (data[2] - '0');
    if (context->phase == SmtpPhase::MessageData &&
        context->responseCode == 354) {
      context->phase = SmtpPhase::Delivery;
    }
  }
  return 0;
}

const char *smtpFailureCategory(CURLcode result, SmtpPhase phase,
                                long responseCode) {
  switch (result) {
  case CURLE_COULDNT_CONNECT:
  case CURLE_OPERATION_TIMEDOUT:
    return "connection failure or timeout";
  case CURLE_USE_SSL_FAILED:
  case CURLE_SSL_CONNECT_ERROR:
  case CURLE_PEER_FAILED_VERIFICATION:
  case CURLE_SSL_CERTPROBLEM:
  case CURLE_SSL_CACERT_BADFILE:
  case CURLE_SSL_CIPHER:
  case CURLE_SSL_ISSUER_ERROR:
    return "TLS negotiation or certificate verification failure";
  case CURLE_LOGIN_DENIED:
    return "SMTP authentication failure";
  default:
    break;
  }

  if ((phase == SmtpPhase::StartTls ||
       phase == SmtpPhase::Authentication) &&
      responseCode >= 400) {
    return phase == SmtpPhase::StartTls
               ? "SMTP server refused STARTTLS"
               : "SMTP authentication rejection";
  }

  if (responseCode >= 400) {
    if (phase == SmtpPhase::Sender) {
      return "SMTP sender rejection";
    }
    if (phase == SmtpPhase::Recipient) {
      return "SMTP recipient rejection";
    }
    if (phase == SmtpPhase::Delivery) {
      return "SMTP server rejected message delivery";
    }
  }

  switch (phase) {
  case SmtpPhase::StartTls:
    return "TLS negotiation failure";
  case SmtpPhase::Authentication:
    return "SMTP authentication exchange failure";
  case SmtpPhase::Sender:
  case SmtpPhase::Recipient:
    return "SMTP connection failed during envelope negotiation";
  case SmtpPhase::Delivery:
    return "SMTP connection failed while submitting message";
  case SmtpPhase::Connection:
    return "SMTP connection or greeting failure";
  case SmtpPhase::MessageData:
  case SmtpPhase::Other:
    return "SMTP protocol or transfer failure";
  }
  return "SMTP protocol or transfer failure";
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
    std::cerr << "[OTP email] SMTP configuration is missing or invalid; "
                 "check SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, "
                 "and SMTP_FROM_EMAIL. Values are not logged."
              << std::endl;
    return false;
  }

  char *end = nullptr;
  config.port = std::strtol(port.c_str(), &end, 10);
  if (end == port.c_str() || *end != '\0' || config.port < 1 ||
      config.port > 65535) {
    std::cerr << "[OTP email] SMTP_PORT must be a number from 1 to 65535."
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
      name.find_first_of("\r\n") != std::string::npos ||
      name.find('\0') != std::string::npos) {
    std::cerr << "[OTP email] Refusing to send due to invalid recipient or "
                 "message fields."
              << std::endl;
    return false;
  }

  SmtpConfig config;
  if (!readConfig(config)) {
    return false;
  }

  static const bool curlInitialized = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
  if (!curlInitialized) {
    std::cerr << "[OTP email] libcurl global initialization failed."
              << std::endl;
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
    std::cerr << "[OTP email] Could not allocate a libcurl SMTP handle."
              << std::endl;
    wipeMessage(message);
    return false;
  }

  curl_slist *recipients = nullptr;
  recipients = curl_slist_append(recipients, ("<" + email + ">").c_str());
  if (!recipients) {
    std::cerr << "[OTP email] Could not allocate the SMTP recipient list."
              << std::endl;
    curl_easy_cleanup(curl);
    wipeMessage(message);
    return false;
  }

  const std::string scheme = config.port == 465 ? "smtps://" : "smtp://";
  const std::string url =
      scheme + config.host + ":" + std::to_string(config.port);
  const std::string envelopeFrom = "<" + config.fromEmail + ">";
  MessageReadContext readContext{message};
  SmtpDebugContext debugContext;
  const auto setOption = [curl](CURLoption option, auto value) {
    return curl_easy_setopt(curl, option, value) == CURLE_OK;
  };
  bool optionsSet =
      setOption(CURLOPT_URL, url.c_str()) &&
      setOption(CURLOPT_USERNAME, config.username.c_str()) &&
      setOption(CURLOPT_PASSWORD, config.password.c_str()) &&
      setOption(CURLOPT_MAIL_FROM, envelopeFrom.c_str()) &&
      setOption(CURLOPT_MAIL_RCPT, recipients) &&
      setOption(CURLOPT_DEBUGFUNCTION, smtpDebugCallback) &&
      setOption(CURLOPT_DEBUGDATA, &debugContext);
  if (config.port != 465) {
    optionsSet = optionsSet &&
                 setOption(CURLOPT_USE_SSL, CURLUSESSL_ALL);
  }
  optionsSet = optionsSet &&
               setOption(CURLOPT_SSL_VERIFYPEER, 1L) &&
               setOption(CURLOPT_SSL_VERIFYHOST, 2L) &&
               setOption(CURLOPT_CONNECTTIMEOUT, 10L) &&
               setOption(CURLOPT_TIMEOUT, 20L) &&
               setOption(CURLOPT_UPLOAD, 1L) &&
               setOption(CURLOPT_READFUNCTION, readMessage) &&
               setOption(CURLOPT_READDATA, &readContext) &&
               setOption(CURLOPT_INFILESIZE_LARGE,
                         static_cast<curl_off_t>(message.size()));

  CURLcode result = CURLE_OK;
  long responseCode = 0;
  if (!optionsSet) {
    std::cerr << "[OTP email] Failed to configure a libcurl SMTP option."
              << std::endl;
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    wipeMessage(message);
    return false;
  } else {
    // Keep verbose output inside the redacting callback; never emit SMTP data.
    result = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    if (result != CURLE_OK) {
      std::cerr << "[OTP email] Failed to enable safe SMTP diagnostics."
                << std::endl;
      curl_slist_free_all(recipients);
      curl_easy_cleanup(curl);
      wipeMessage(message);
      return false;
    }
    result = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
  }

  if (debugContext.responseCode != 0) {
    responseCode = debugContext.responseCode;
  }
  curl_slist_free_all(recipients);
  curl_easy_cleanup(curl);
  wipeMessage(message);
  if (result != CURLE_OK) {
    std::cerr << "[OTP email] "
              << smtpFailureCategory(result, debugContext.phase, responseCode)
              << " (libcurl=" << static_cast<int>(result)
              << ", SMTP response=" << responseCode
              << "). No credentials, addresses, or OTP values were logged."
              << std::endl;
    return false;
  }
  return true;
}
