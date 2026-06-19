import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse


DEFAULT_KEYWORDS: Dict[str, List[str]] = {
    "money_lure": [
        "지원금", "피해지원금", "환급금", "보상금", "보험환급금", "정부지원", "당첨", "무료",
        "혜택", "이벤트", "상품권", "쿠폰", "포인트", "캐시백", "보상", "충전", "gift", "egift",
        "giveaway", "free", "premium", "promo", "promotion", "nitro", "3 month", "3 months",
        "get 3 month", "claim", "redeem", "get",
    ],
    "institution_impersonation": [
        "경찰청", "검찰", "검찰청", "법원", "국세청", "금융감독원", "건강보험", "국민건강보험",
        "정부24", "민원24", "관세청", "우체국", "카카오뱅크", "국민은행", "신한은행", "우리카드",
        "카드", "kt", "skt", "lg u+", "통신사", "steam", "discord", "discord nitro",
    ],
    "delivery": [
        "택배", "배송", "주소 확인", "주소지 확인", "반송", "미수령", "수령", "통관", "우편물",
        "등기", "운송장", "배송지", "카드 배송", "카드 수령",
    ],
    "personal_info": [
        "주민등록번호", "주민번호", "계좌번호", "카드번호", "개인정보", "신분증", "여권번호",
        "보안카드", "otp", "OTP", "인증서", "공동인증서", "금융정보", "주소 입력",
    ],
    "auth_request": [
        "인증번호", "승인번호", "비밀번호", "비번", "본인확인", "본인 인증", "휴대폰 인증",
        "로그인", "재인증", "보안인증", "인증코드",
    ],
    "app_install": [
        "앱 설치", "어플 설치", "설치파일", "apk", "APK", "원격제어", "원격 지원", "원격앱",
        "팀뷰어", "다운로드 후 실행", "보안앱", "악성앱", "설치하세요",
    ],
    "urgency": [
        "즉시", "긴급", "오늘까지", "마감", "미납", "연체", "차단", "정지", "압류", "형사처벌",
        "수사", "소환", "기한", "제한", "offer ends", "expires", "expired", "limited time", "last chance",
    ],
    "contact_request": [
        "연락", "전화", "문의", "고객센터", "상담", "확인 바랍니다", "회신", "즉시 연락", "클릭",
        "접속", "확인하세요", "입력", "update", "customize", "share your screen",
    ],
}

CATEGORY_WEIGHTS = {
    "money_lure": 3,
    "institution_impersonation": 3,
    "delivery": 2,
    "personal_info": 5,
    "auth_request": 5,
    "app_install": 6,
    "urgency": 2,
    "contact_request": 1,
}

OFFICIAL_DOMAINS = {
    "go.kr", "gov.kr", "mil.kr", "korea.kr", "data.go.kr", "boho.or.kr", "kisa.or.kr",
    "krnic.or.kr", "counterscam112.go.kr", "mobileid.go.kr", "police.go.kr", "spo.go.kr",
    "fss.or.kr", "nhis.or.kr", "nts.go.kr", "epost.go.kr", "customs.go.kr", "mois.go.kr",
    "mofa.go.kr", "moef.go.kr", "mohw.go.kr", "moel.go.kr", "molit.go.kr", "mcst.go.kr",
    "me.go.kr", "mafra.go.kr", "moj.go.kr", "motie.go.kr", "msit.go.kr", "mpva.go.kr",
    "mss.go.kr", "kipo.go.kr", "kostat.go.kr", "kma.go.kr", "nfa.go.kr", "safekorea.go.kr",
    "safenet.go.kr", "scourt.go.kr", "cjlogistics.com", "kakaobank.com", "kt.com",
    "ktmmobile.com", "tworld.co.kr", "sktelecom.com", "lguplus.com", "uplus.co.kr",
    "uplusumobile.com", "sk7mobile.com", "discord.com", "discordapp.com", "discord.gg",
    "steampowered.com", "steamcommunity.com",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly",
    "vo.la", "han.gl", "me2.do", "url.kr", "shorturl.at", "buff.ly", "lnkd.in",
}

FREE_HOSTING_DOMAINS = {
    "web.app", "firebaseapp.com", "github.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "notion.site",
}

SUSPICIOUS_TLDS = {"shop", "site", "xyz", "top", "click", "quest", "monster", "cam", "icu"}

BRAND_RULES: Dict[str, Dict[str, Iterable[str]]] = {
    "discord": {
        "tokens": ("discord", "discord nitro", "nitro"),
        "domains": ("discord.com", "discordapp.com", "discord.gg"),
    },
    "steam": {
        "tokens": ("steam",),
        "domains": ("steampowered.com", "steamcommunity.com"),
    },
    "kakao_bank": {
        "tokens": ("카카오뱅크", "kakaobank"),
        "domains": ("kakaobank.com",),
    },
    "epost": {
        "tokens": ("우체국", "인터넷우체국"),
        "domains": ("epost.go.kr",),
    },
    "cj": {
        "tokens": ("cj대한통운", "대한통운", "cj logistics"),
        "domains": ("cjlogistics.com",),
    },
    "police": {
        "tokens": ("경찰청",),
        "domains": ("police.go.kr", "counterscam112.go.kr"),
    },
    "gov24": {
        "tokens": ("정부24", "민원24"),
        "domains": ("gov.kr", "go.kr", "korea.kr"),
    },
}

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>'\"\])}]+", re.IGNORECASE)
TRAILING_PUNCTUATION = ".,!?;:)]}>\"'"
PERSONAL_SENDER_RE = re.compile(r"^(?:\+?82[- ]?)?0?1[016789][- ]?\d{3,4}[- ]?\d{4}$")


@dataclass
class UrlFinding:
    raw_url: str
    normalized_url: str
    domain: str
    is_official: bool = False
    is_shortener: bool = False
    is_ip_address: bool = False
    is_free_hosting: bool = False
    has_suspicious_tld: bool = False
    uses_http: bool = False
    brand_mismatch: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    message: str
    sender: Optional[str]
    score: int
    level: str
    reasons: List[str]
    keywords: Dict[str, List[str]]
    urls: List[UrlFinding]


def extract_urls(message: str) -> List[str]:
    urls: List[str] = []
    for match in URL_RE.findall(message or ""):
        cleaned = match.strip().rstrip(TRAILING_PUNCTUATION)
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls


def normalize_url(url: str) -> str:
    if url.lower().startswith("www."):
        return "http://" + url
    return url


def get_domain(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    host = (parsed.hostname or "").lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def domain_matches(domain: str, official_domain: str) -> bool:
    domain = domain.lower().strip(".")
    official_domain = official_domain.lower().strip(".")
    return domain == official_domain or domain.endswith("." + official_domain)


def is_official_domain(domain: str, official_domains: Iterable[str] = OFFICIAL_DOMAINS) -> bool:
    return any(domain_matches(domain, official) for official in official_domains)


def is_ip_domain(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def get_tld(domain: str) -> str:
    if "." not in domain:
        return ""
    return domain.rsplit(".", 1)[-1]


def contains_any(text: str, words: Iterable[str]) -> bool:
    lower = text.lower()
    return any(word.lower() in lower for word in words)


def find_keywords(message: str, keyword_map: Optional[Dict[str, List[str]]] = None) -> Dict[str, List[str]]:
    keyword_map = keyword_map or DEFAULT_KEYWORDS
    lower = (message or "").lower()
    found: Dict[str, List[str]] = {}
    for category, words in keyword_map.items():
        hits = []
        for word in words:
            if word.lower() in lower and word not in hits:
                hits.append(word)
        if hits:
            found[category] = hits
    return found


def is_personal_sender(sender: Optional[str]) -> bool:
    if not sender:
        return False
    compact = re.sub(r"\s+", "", sender.strip())
    return bool(PERSONAL_SENDER_RE.match(compact))


def mentioned_brands(message: str) -> Set[str]:
    lower = (message or "").lower()
    brands: Set[str] = set()
    for brand, rule in BRAND_RULES.items():
        if any(token.lower() in lower for token in rule["tokens"]):
            brands.add(brand)
    return brands


def official_domains_for_brands(brands: Iterable[str]) -> Set[str]:
    domains: Set[str] = set()
    for brand in brands:
        domains.update(str(domain).lower() for domain in BRAND_RULES[brand]["domains"])
    return domains


def analyze_urls(
    message: str,
    official_domains: Iterable[str] = OFFICIAL_DOMAINS,
) -> Tuple[List[UrlFinding], List[str], int, bool]:
    findings: List[UrlFinding] = []
    reasons: List[str] = []
    score = 0
    has_nonofficial_url = False
    brands = mentioned_brands(message)
    expected_brand_domains = official_domains_for_brands(brands)

    urls = extract_urls(message)
    if urls:
        score += 1
        reasons.append("URL 포함 +1")

    for raw_url in urls:
        normalized_url = normalize_url(raw_url)
        parsed = urlparse(normalized_url)
        domain = get_domain(raw_url)
        finding = UrlFinding(raw_url=raw_url, normalized_url=normalized_url, domain=domain)

        finding.uses_http = parsed.scheme.lower() == "http"
        finding.is_official = is_official_domain(domain, official_domains)
        finding.is_shortener = is_official_domain(domain, SHORTENER_DOMAINS)
        finding.is_ip_address = is_ip_domain(domain)
        finding.is_free_hosting = is_official_domain(domain, FREE_HOSTING_DOMAINS)
        finding.has_suspicious_tld = get_tld(domain) in SUSPICIOUS_TLDS

        if finding.is_official:
            score -= 3
            finding.notes.append("공식 도메인 감점")
            reasons.append(f"공식 도메인({domain}) -3")
        else:
            has_nonofficial_url = True

        if finding.is_shortener:
            score += 4
            finding.notes.append("단축 URL")
            reasons.append(f"단축 URL({domain}) +4")
        if finding.is_ip_address:
            score += 5
            finding.notes.append("IP 주소 URL")
            reasons.append(f"IP 주소 URL({domain}) +5")
        if finding.is_free_hosting:
            score += 3
            finding.notes.append("무료 호스팅 도메인")
            reasons.append(f"무료 호스팅 도메인({domain}) +3")
        if finding.has_suspicious_tld:
            score += 3
            finding.notes.append("의심 TLD")
            reasons.append(f"의심 TLD(.{get_tld(domain)}) +3")

        if brands and expected_brand_domains and not any(domain_matches(domain, d) for d in expected_brand_domains):
            finding.brand_mismatch = True
            finding.notes.append("브랜드명과 URL 도메인 불일치")

        findings.append(finding)

    if any(f.brand_mismatch for f in findings):
        score += 5
        reasons.append("브랜드명과 URL 도메인 불일치 +5")

    return findings, reasons, score, has_nonofficial_url


def is_safe_auth_notice(message: str, keywords: Dict[str, List[str]], has_nonofficial_url: bool) -> bool:
    if "auth_request" not in keywords:
        return False
    if has_nonofficial_url:
        return False
    dangerous = {"money_lure", "personal_info", "app_install"}
    if any(category in keywords for category in dangerous):
        return False
    safety_words = [
        "타인에게 알려주지", "직원에게도 알려주지", "절대 알려주지", "본인이 요청", "요청하신",
        "입력하지 마세요", "알려주지 마세요", "본인 요청이 아니면", "도용 방지",
    ]
    return contains_any(message, safety_words)


def classify(score: int) -> str:
    if score >= 9:
        return "고위험"
    if score >= 6:
        return "위험"
    if score >= 3:
        return "의심"
    return "정상 가능성 높음"


def detect_message(
    message: str,
    sender: Optional[str] = None,
    keyword_map: Optional[Dict[str, List[str]]] = None,
    official_domains: Optional[Iterable[str]] = None,
) -> DetectionResult:
    message = message or ""
    official_domains = list(official_domains or OFFICIAL_DOMAINS)
    keywords = find_keywords(message, keyword_map)
    urls, reasons, url_score, has_nonofficial_url = analyze_urls(message, official_domains)

    score = url_score
    for category, hits in keywords.items():
        weight = CATEGORY_WEIGHTS.get(category, 1)
        score += weight
        shown = ", ".join(hits[:6])
        reasons.append(f"{category} 키워드({shown}) +{weight}")

    categories = set(keywords)
    has_url = bool(urls)

    if has_nonofficial_url and "money_lure" in categories:
        score += 4
        reasons.append("비공식 URL + 금전/혜택 유인 조합 +4")
    if has_nonofficial_url and "institution_impersonation" in categories:
        score += 4
        reasons.append("비공식 URL + 기관/브랜드 사칭 조합 +4")
    if has_nonofficial_url and "delivery" in categories:
        score += 3
        reasons.append("비공식 URL + 택배/배송 조합 +3")
    if has_url and "personal_info" in categories:
        score += 5
        reasons.append("URL + 개인정보 요구 조합 +5")
    if has_url and "app_install" in categories:
        score += 6
        reasons.append("URL + 앱 설치 요구 조합 +6")
    if {"delivery", "contact_request"}.issubset(categories):
        score += 2
        reasons.append("배송/수령 안내 + 연락/접속 유도 조합 +2")
    if is_personal_sender(sender) and categories.intersection({"institution_impersonation", "delivery"}):
        score += 3
        reasons.append("개인번호 발신 + 기관/금융/배송 사칭 조합 +3")
    if has_nonofficial_url and categories.intersection({"money_lure", "urgency"}) and contains_any(message, ["offer ends", "limited time", "last chance", "claim", "redeem"]):
        score += 3
        reasons.append("비공식 URL + 혜택/긴급 마감 문구 조합 +3")
    if has_nonofficial_url and "urgency" in categories and "contact_request" in categories:
        score += 3
        reasons.append("긴급성 + 링크 행동 유도 + 비공식 URL 조합 +3")

    if is_safe_auth_notice(message, keywords, has_nonofficial_url):
        if score > 2:
            reasons.append("정상 인증번호 안전 안내 문맥: 점수 2점으로 보정")
        score = min(score, 2)

    score = max(score, 0)
    level = classify(score)
    if not reasons:
        reasons.append("명확한 위험 신호 없음")

    return DetectionResult(
        message=message,
        sender=sender,
        score=score,
        level=level,
        reasons=reasons,
        keywords=keywords,
        urls=urls,
    )
