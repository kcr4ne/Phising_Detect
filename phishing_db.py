import json
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from phishing_detector import DEFAULT_KEYWORDS, OFFICIAL_DOMAINS, DetectionResult


DEFAULT_DB_PATH = "phishing_rules.db"


EXAMPLE_MESSAGES: List[Tuple[str, str, str]] = [
    (
        "정상 가능성 높음",
        "카카오뱅크 이벤트 안내 https://www.kakaobank.com/event",
        "공식 도메인을 사용하는 일반 이벤트 안내",
    ),
    (
        "정상 가능성 높음",
        "[KT] 요청하신 본인확인 인증번호는 123456입니다. 타인에게 알려주지 마세요.",
        "정상 인증번호 안전 안내",
    ),
    (
        "의심",
        "행사 안내 https://example.com/event",
        "비공식 일반 URL 안내",
    ),
    (
        "위험",
        "[우체국] 택배 주소 확인이 필요합니다. https://epost-help.shop 접속 후 확인하세요.",
        "배송 사칭 + 비공식 URL",
    ),
    (
        "고위험",
        "Discord Nitro distribution from STEAM. Get 3 month of Discord Nitro. Offer ends July 10, 2022 at 11am EDT. https://egift-premium.ru/promo",
        "브랜드 사칭 + 비공식 URL + 영문 혜택 미끼",
    ),
    (
        "고위험",
        "[경찰청] 교통범칙금 미납 통지서입니다. https://police-pay.xyz 에서 즉시 납부하세요.",
        "공공기관 사칭 + 미납/긴급 + 의심 도메인",
    ),
]


def connect(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True) if Path(db_path).parent != Path(".") else None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: str = DEFAULT_DB_PATH) -> None:
    with connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keywords (
                category TEXT NOT NULL,
                keyword TEXT NOT NULL,
                PRIMARY KEY (category, keyword)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS official_domains (
                domain TEXT PRIMARY KEY
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS examples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                expected_level TEXT NOT NULL,
                message TEXT NOT NULL,
                description TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                sender TEXT,
                message TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                urls_json TEXT NOT NULL,
                keywords_json TEXT NOT NULL
            )
            """
        )
        seed_defaults(conn)


def seed_defaults(conn: sqlite3.Connection) -> None:
    for category, words in DEFAULT_KEYWORDS.items():
        conn.executemany(
            "INSERT OR IGNORE INTO keywords(category, keyword) VALUES(?, ?)",
            [(category, word) for word in words],
        )
    conn.executemany(
        "INSERT OR IGNORE INTO official_domains(domain) VALUES(?)",
        [(domain,) for domain in sorted(OFFICIAL_DOMAINS)],
    )
    count = conn.execute("SELECT COUNT(*) FROM examples").fetchone()[0]
    if count == 0:
        conn.executemany(
            "INSERT INTO examples(expected_level, message, description) VALUES(?, ?, ?)",
            EXAMPLE_MESSAGES,
        )
    conn.commit()


def load_keywords(db_path: str = DEFAULT_DB_PATH) -> Dict[str, List[str]]:
    init_database(db_path)
    keyword_map: Dict[str, List[str]] = {}
    with connect(db_path) as conn:
        rows = conn.execute("SELECT category, keyword FROM keywords ORDER BY category, keyword").fetchall()
    for row in rows:
        keyword_map.setdefault(row["category"], []).append(row["keyword"])
    return keyword_map or DEFAULT_KEYWORDS


def load_official_domains(db_path: str = DEFAULT_DB_PATH) -> List[str]:
    init_database(db_path)
    with connect(db_path) as conn:
        rows = conn.execute("SELECT domain FROM official_domains ORDER BY domain").fetchall()
    return [row["domain"] for row in rows] or sorted(OFFICIAL_DOMAINS)


def load_examples(db_path: str = DEFAULT_DB_PATH) -> List[Tuple[str, str, str]]:
    init_database(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT expected_level, message, description FROM examples ORDER BY id"
        ).fetchall()
    return [(row["expected_level"], row["message"], row["description"]) for row in rows]


def log_scan(result: DetectionResult, db_path: str = DEFAULT_DB_PATH) -> None:
    init_database(db_path)
    urls = [
        {
            "raw_url": item.raw_url,
            "domain": item.domain,
            "is_official": item.is_official,
            "notes": item.notes,
        }
        for item in result.urls
    ]
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_logs(sender, message, score, level, reasons_json, urls_json, keywords_json)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.sender,
                result.message,
                result.score,
                result.level,
                json.dumps(result.reasons, ensure_ascii=False),
                json.dumps(urls, ensure_ascii=False),
                json.dumps(result.keywords, ensure_ascii=False),
            ),
        )
        conn.commit()


def add_keyword(category: str, keyword: str, db_path: str = DEFAULT_DB_PATH) -> None:
    init_database(db_path)
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO keywords(category, keyword) VALUES(?, ?)",
            (category.strip(), keyword.strip()),
        )
        conn.commit()


def add_official_domain(domain: str, db_path: str = DEFAULT_DB_PATH) -> None:
    init_database(db_path)
    with connect(db_path) as conn:
        conn.execute("INSERT OR IGNORE INTO official_domains(domain) VALUES(?)", (domain.lower().strip(),))
        conn.commit()


def latest_logs(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[sqlite3.Row]:
    init_database(db_path)
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM scan_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
