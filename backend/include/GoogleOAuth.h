#ifndef GOOGLE_OAUTH_H
#define GOOGLE_OAUTH_H

#include <optional>
#include <string>

struct GoogleIdentity {
    std::string subject;
    std::string email;
    std::string name;
};

namespace GoogleOAuth {
bool isConfigured();
// Only identities returned by Google's authenticated userinfo endpoint are trusted.
std::optional<GoogleIdentity> exchangeCode(const std::string& code,
                                          const std::string& origin);
}

#endif
