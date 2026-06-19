from phishing_detector import detect_message


LEVEL_ORDER = {"정상 가능성 높음": 0, "의심": 1, "위험": 2, "고위험": 3}

SCENARIOS = [
    ("공식 은행 URL", "카카오뱅크 이벤트 안내 https://www.kakaobank.com/event", "정상 가능성 높음", "의심"),
    ("정상 인증번호", "[KT] 요청하신 본인확인 인증번호는 123456입니다. 타인에게 알려주지 마세요.", "정상 가능성 높음", "정상 가능성 높음"),
    ("일반 행사 URL", "행사 안내 https://example.com/event", "정상 가능성 높음", "의심"),
    ("배송 사칭", "[우체국] 택배 주소 확인 https://epost-help.shop", "위험", None),
    ("공공기관 사칭", "[경찰청] 교통범칙금 미납 통지서 https://police-pay.xyz 즉시 납부", "고위험", None),
    ("가짜 통신사 인증", "[통신사] 보안인증 필요. 개인정보 입력 후 인증하세요 https://kt-security.site", "고위험", None),
    ("Discord/Steam 사칭", "Discord Nitro distribution from STEAM. Get 3 month of Discord Nitro. Offer ends July 10, 2022 at 11am EDT. https://egift-premium.ru/promo", "고위험", None),
    ("정상 가족 대화", "엄마 오늘 저녁 같이 먹자", "정상 가능성 높음", "정상 가능성 높음"),
]


def within_range(level: str, minimum: str, maximum: str | None) -> bool:
    if LEVEL_ORDER[level] < LEVEL_ORDER[minimum]:
        return False
    if maximum is not None and LEVEL_ORDER[level] > LEVEL_ORDER[maximum]:
        return False
    return True


def main() -> None:
    failures = []
    for name, message, minimum, maximum in SCENARIOS:
        result = detect_message(message)
        print(f"[{name}] {result.level} / {result.score}점")
        if not within_range(result.level, minimum, maximum):
            failures.append((name, result.level, result.score, result.reasons))
    if failures:
        print("\n실패 시나리오:")
        for name, level, score, reasons in failures:
            print(f"- {name}: {level} / {score}점 / {reasons}")
        raise SystemExit(1)
    print("\n모든 스모크 시나리오 통과")


if __name__ == "__main__":
    main()
