#include "GoogleOAuth.h"
#include "Encryption.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <memory>

namespace {
using json = nlohmann::json;

bool initializeCurl() {
    static const bool ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
    return ready;
}

size_t receiveBody(char* data, size_t size, size_t count, void* context) {
    auto& body = *static_cast<std::string*>(context);
    const size_t bytes = size * count;
    if (bytes > 65536 - body.size()) return 0;
    try { body.append(data, bytes); }
    catch (...) { return 0; }
    return bytes;
}

struct WipeString {
    std::string& value;
    ~WipeString() { Encryption::wipeString(value); }
};

std::optional<json> request(CURL* handle) {
    std::string body;
    WipeString wipe{body};
    if (curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, receiveBody) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &body) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 5L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_TIMEOUT, 10L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_perform(handle) != CURLE_OK) return std::nullopt;
    long status = 0;
    if (curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
        status != 200) return std::nullopt;
    auto result = json::parse(body, nullptr, false);
    if (!result.is_object()) return std::nullopt;
    return result;
}
}

bool GoogleOAuth::isConfigured() {
    const auto* id = std::getenv("GOOGLE_CLIENT_ID");
    const auto* secret = std::getenv("GOOGLE_CLIENT_SECRET");
    return id && *id && secret && *secret;
}

std::optional<GoogleIdentity> GoogleOAuth::exchangeCode(const std::string& code,
                                                       const std::string& origin) {
    if (!isConfigured() || code.empty() || code.size() > 4096 ||
        origin.empty() || origin.size() > 2048 || !initializeCurl()) return std::nullopt;
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
    if (!handle) return std::nullopt;
    auto encode = [&](const std::string& value) {
        std::unique_ptr<char, decltype(&curl_free)> encoded(
            curl_easy_escape(handle.get(), value.data(), static_cast<int>(value.size())), curl_free);
        if (!encoded) throw std::bad_alloc();
        return std::string(encoded.get());
    };
    try {
        // In GIS popup mode the redirect URI is the frontend's origin.
        std::string form = "grant_type=authorization_code&code=" + encode(code) +
            "&client_id=" + encode(std::getenv("GOOGLE_CLIENT_ID")) +
            "&client_secret=" + encode(std::getenv("GOOGLE_CLIENT_SECRET")) +
            "&redirect_uri=" + encode(origin);
        WipeString wipeForm{form};
        if (curl_easy_setopt(handle.get(), CURLOPT_URL, "https://oauth2.googleapis.com/token") != CURLE_OK ||
            curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDS, form.c_str()) != CURLE_OK)
            return std::nullopt;
        auto tokens = request(handle.get());
        if (!tokens || !tokens->contains("access_token") ||
            !(*tokens)["access_token"].is_string()) return std::nullopt;
        std::string accessToken = (*tokens)["access_token"].get<std::string>();
        WipeString wipeToken{accessToken};
        if (accessToken.empty() || accessToken.find_first_of("\r\n") != std::string::npos)
            return std::nullopt;
        curl_easy_reset(handle.get());
        if (curl_easy_setopt(handle.get(), CURLOPT_URL, "https://openidconnect.googleapis.com/v1/userinfo") != CURLE_OK ||
            curl_easy_setopt(handle.get(), CURLOPT_HTTPAUTH, CURLAUTH_BEARER) != CURLE_OK ||
            curl_easy_setopt(handle.get(), CURLOPT_XOAUTH2_BEARER, accessToken.c_str()) != CURLE_OK)
            return std::nullopt;
        const auto profile = request(handle.get());
        if (!profile || !profile->contains("sub") || !(*profile)["sub"].is_string() ||
            !profile->contains("email") || !(*profile)["email"].is_string() ||
            !profile->contains("email_verified") || (*profile)["email_verified"] != true)
            return std::nullopt;
        GoogleIdentity identity{(*profile)["sub"].get<std::string>(),
                                (*profile)["email"].get<std::string>(), ""};
        if (profile->contains("name") && (*profile)["name"].is_string())
            identity.name = (*profile)["name"].get<std::string>();
        if (identity.subject.empty() || identity.subject.size() > 255 ||
            identity.email.empty() || identity.email.size() > 254 || identity.name.size() > 200)
            return std::nullopt;
        return identity;
    } catch (...) {
        return std::nullopt;
    }
}
