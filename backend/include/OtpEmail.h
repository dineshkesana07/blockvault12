#ifndef OTP_EMAIL_H
#define OTP_EMAIL_H

#include <string>

class OtpEmail {
public:
  static bool isConfigured();
  static bool sendVerificationCode(const std::string &email,
                                   const std::string &otp);
};

#endif // OTP_EMAIL_H
