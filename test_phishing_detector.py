import unittest

from phishing_detector import detect_message, extract_urls, get_domain


class PhishingDetectorTest(unittest.TestCase):
    LEVEL_ORDER = {
        "정상 가능성 높음": 0,
        "의심": 1,
        "위험": 2,
        "고위험": 3,
    }

    def assert_at_least(self, result, expected_level):
        self.assertGreaterEqual(self.LEVEL_ORDER[result.level], self.LEVEL_ORDER[expected_level], result.reasons)

    def assert_at_most(self, result, expected_level):
        self.assertLessEqual(self.LEVEL_ORDER[result.level], self.LEVEL_ORDER[expected_level], result.reasons)

    def test_extract_urls(self):
        urls = extract_urls("확인 https://example.com/a, 또는 www.test.com")
        self.assertEqual(urls, ["https://example.com/a", "www.test.com"])

    def test_get_domain(self):
        self.assertEqual(get_domain("https://www.kakaobank.com/event"), "kakaobank.com")

    def test_official_url_is_not_automatically_blocked(self):
        result = detect_message("카카오뱅크 이벤트 안내 https://www.kakaobank.com/event")
        self.assert_at_most(result, "의심")
        self.assertTrue(any("공식 도메인" in reason for reason in result.reasons))

    def test_official_url_can_still_be_dangerous_with_app_install(self):
        result = detect_message("정부24 보안앱 APK 설치 후 개인정보를 입력하세요 https://www.gov.kr")
        self.assert_at_least(result, "위험")

    def test_normal_auth_code_notice_is_not_high_risk(self):
        result = detect_message("[KT] 요청하신 본인확인 인증번호는 123456입니다. 타인에게 알려주지 마세요.")
        self.assertEqual(result.level, "정상 가능성 높음")
        self.assertLessEqual(result.score, 2)

    def test_fake_telecom_auth_page_is_high_risk(self):
        result = detect_message("[통신사] 보안인증 필요. 개인정보 입력 후 인증하세요 https://kt-security.site", "010-1234-5678")
        self.assertEqual(result.level, "고위험")

    def test_discord_steam_gift_scam_is_high_risk(self):
        message = (
            "Discord Nitro distribution from STEAM.\n"
            "Get 3 month of Discord Nitro. Offer ends July 10, 2022 at 11am EDT. "
            "Customize your profile, share your screen in HD, update your emoji and more!\n"
            "https://egift-premium.ru/promo"
        )
        result = detect_message(message)
        self.assertEqual(result.level, "고위험")
        self.assertTrue(any("브랜드명과 URL 도메인 불일치" in reason for reason in result.reasons))

    def test_short_url_is_risky(self):
        result = detect_message("지원금 신청 https://bit.ly/help-now")
        self.assert_at_least(result, "위험")

    def test_ip_address_url_is_risky(self):
        result = detect_message("보안 인증 https://192.168.0.10/login")
        self.assert_at_least(result, "위험")

    def test_delivery_with_nonofficial_url_is_risky(self):
        result = detect_message("[우체국] 택배 주소 확인 https://epost-help.shop")
        self.assert_at_least(result, "위험")

    def test_plain_family_message_is_safe(self):
        result = detect_message("엄마 오늘 저녁 같이 먹자")
        self.assertEqual(result.level, "정상 가능성 높음")


if __name__ == "__main__":
    unittest.main()
