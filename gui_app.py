import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from phishing_db import (
    DEFAULT_DB_PATH,
    init_database,
    load_examples,
    load_keywords,
    load_official_domains,
    log_scan,
)
from phishing_detector import DetectionResult, detect_message


APP_BG = "#EEF2F7"
PANEL_BG = "#FFFFFF"
TEXT = "#172033"
MUTED = "#64748B"
BORDER = "#D8DEE9"
ACCENT = "#2563EB"
DANGER = "#DC2626"
WARNING = "#F59E0B"
SAFE = "#16A34A"

LEVEL_COLORS = {
    "정상 가능성 높음": SAFE,
    "의심": WARNING,
    "위험": "#EA580C",
    "고위험": DANGER,
}


def get_db_path() -> str:
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve().parent / DEFAULT_DB_PATH)
    return str(Path(__file__).resolve().parent / DEFAULT_DB_PATH)


class PhishingDetectorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.db_path = get_db_path()
        init_database(self.db_path)
        self.keyword_map = load_keywords(self.db_path)
        self.official_domains = load_official_domains(self.db_path)
        self.examples = load_examples(self.db_path)
        self.last_result: DetectionResult | None = None

        self.root.title("피싱 문자 탐지기")
        self.root.geometry("1120x760")
        self.root.minsize(980, 680)
        self.root.configure(bg=APP_BG)

        self.configure_style()
        self.build_layout()

    def configure_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", font=("Malgun Gothic", 10), rowheight=28, borderwidth=0)
        style.configure("Treeview.Heading", font=("Malgun Gothic", 10, "bold"), background="#E2E8F0")
        style.configure("TButton", font=("Malgun Gothic", 10, "bold"), padding=(12, 8))
        style.configure("Accent.TButton", background=ACCENT, foreground="white")

    def build_layout(self) -> None:
        header = tk.Frame(self.root, bg="#111827", height=74)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="피싱 문자 탐지기", bg="#111827", fg="white", font=("Malgun Gothic", 20, "bold")).pack(side="left", padx=26)
        tk.Label(header, text="URL, 도메인, 키워드, 발신번호 조합으로 위험도를 계산합니다.", bg="#111827", fg="#CBD5E1", font=("Malgun Gothic", 10)).pack(side="left", padx=8)

        main = tk.Frame(self.root, bg=APP_BG)
        main.pack(fill="both", expand=True, padx=18, pady=18)
        main.columnconfigure(0, weight=11)
        main.columnconfigure(1, weight=9)
        main.rowconfigure(0, weight=1)

        left = self.panel(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        right = self.panel(main)
        right.grid(row=0, column=1, sticky="nsew", padx=(9, 0))

        self.build_input_panel(left)
        self.build_result_panel(right)

    def panel(self, parent: tk.Widget) -> tk.Frame:
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground=BORDER, highlightthickness=1)
        return frame

    def label(self, parent: tk.Widget, text: str, size: int = 11, bold: bool = False, color: str = TEXT) -> tk.Label:
        weight = "bold" if bold else "normal"
        return tk.Label(parent, text=text, bg=PANEL_BG, fg=color, font=("Malgun Gothic", size, weight), anchor="w")

    def build_input_panel(self, parent: tk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        self.label(parent, "검사할 문자", 14, True).grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))

        self.message_text = tk.Text(parent, height=10, wrap="word", font=("Malgun Gothic", 11), relief="flat", bd=0, bg="#F8FAFC", fg=TEXT, insertbackground=TEXT)
        self.message_text.grid(row=1, column=0, sticky="nsew", padx=18)
        parent.rowconfigure(1, weight=1)

        sender_row = tk.Frame(parent, bg=PANEL_BG)
        sender_row.grid(row=2, column=0, sticky="ew", padx=18, pady=(14, 8))
        sender_row.columnconfigure(1, weight=1)
        self.label(sender_row, "발신번호", 10, True).grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.sender_entry = tk.Entry(sender_row, font=("Malgun Gothic", 11), relief="flat", bg="#F8FAFC", fg=TEXT)
        self.sender_entry.grid(row=0, column=1, sticky="ew", ipady=7)

        button_row = tk.Frame(parent, bg=PANEL_BG)
        button_row.grid(row=3, column=0, sticky="ew", padx=18, pady=(4, 18))
        ttk.Button(button_row, text="판단하기", style="Accent.TButton", command=self.run_detection).pack(side="left")
        ttk.Button(button_row, text="지우기", command=self.clear_input).pack(side="left", padx=8)
        ttk.Button(button_row, text="결과 복사", command=self.copy_result).pack(side="left")

        self.label(parent, "테스트 예시", 13, True).grid(row=4, column=0, sticky="ew", padx=18, pady=(4, 8))
        self.example_tree = ttk.Treeview(parent, columns=("level", "message"), show="headings", height=8)
        self.example_tree.heading("level", text="예상 판정")
        self.example_tree.heading("message", text="문자 예시")
        self.example_tree.column("level", width=130, minwidth=130, stretch=False, anchor="center")
        self.example_tree.column("message", width=520, minwidth=280, stretch=True)
        self.example_tree.grid(row=5, column=0, sticky="nsew", padx=18, pady=(0, 18))
        parent.rowconfigure(5, weight=1)
        for index, example in enumerate(self.examples):
            level, message, description = example
            self.example_tree.insert("", "end", iid=str(index), values=(level, message))
        self.example_tree.bind("<<TreeviewSelect>>", self.load_selected_example)

    def build_result_panel(self, parent: tk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        self.level_var = tk.StringVar(value="검사 전")
        self.score_var = tk.StringVar(value="0점")

        card = tk.Frame(parent, bg="#F8FAFC", highlightbackground=BORDER, highlightthickness=1)
        card.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 12))
        card.columnconfigure(0, weight=1)
        tk.Label(card, textvariable=self.level_var, bg="#F8FAFC", fg=TEXT, font=("Malgun Gothic", 22, "bold")).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 2))
        tk.Label(card, textvariable=self.score_var, bg="#F8FAFC", fg=MUTED, font=("Malgun Gothic", 12, "bold")).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 12))

        self.score_canvas = tk.Canvas(parent, height=18, bg=PANEL_BG, highlightthickness=0)
        self.score_canvas.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 16))
        self.score_canvas.bind("<Configure>", lambda _event: self.draw_score_bar())

        self.label(parent, "탐지 URL", 12, True).grid(row=2, column=0, sticky="ew", padx=18, pady=(2, 6))
        self.url_tree = ttk.Treeview(parent, columns=("domain", "official", "notes"), show="headings", height=5)
        self.url_tree.heading("domain", text="도메인")
        self.url_tree.heading("official", text="공식 여부")
        self.url_tree.heading("notes", text="분석")
        self.url_tree.column("domain", width=180, stretch=True)
        self.url_tree.column("official", width=90, stretch=False, anchor="center")
        self.url_tree.column("notes", width=260, stretch=True)
        self.url_tree.grid(row=3, column=0, sticky="nsew", padx=18, pady=(0, 14))
        parent.rowconfigure(3, weight=1)

        self.label(parent, "탐지 키워드", 12, True).grid(row=4, column=0, sticky="ew", padx=18, pady=(0, 6))
        self.keyword_text = tk.Text(parent, height=5, wrap="word", font=("Malgun Gothic", 10), relief="flat", bg="#F8FAFC", fg=TEXT)
        self.keyword_text.grid(row=5, column=0, sticky="nsew", padx=18, pady=(0, 14))
        parent.rowconfigure(5, weight=1)

        self.label(parent, "판단 근거", 12, True).grid(row=6, column=0, sticky="ew", padx=18, pady=(0, 6))
        self.reason_text = tk.Text(parent, height=8, wrap="word", font=("Malgun Gothic", 10), relief="flat", bg="#F8FAFC", fg=TEXT)
        self.reason_text.grid(row=7, column=0, sticky="nsew", padx=18, pady=(0, 18))
        parent.rowconfigure(7, weight=2)

    def load_selected_example(self, _event=None) -> None:
        selected = self.example_tree.selection()
        if not selected:
            return
        level, message, description = self.examples[int(selected[0])]
        self.message_text.delete("1.0", "end")
        self.message_text.insert("1.0", message)

    def run_detection(self) -> None:
        message = self.message_text.get("1.0", "end").strip()
        sender = self.sender_entry.get().strip() or None
        if not message:
            messagebox.showwarning("입력 필요", "검사할 문자 내용을 입력하세요.")
            return
        result = detect_message(message, sender, self.keyword_map, self.official_domains)
        self.last_result = result
        log_scan(result, self.db_path)
        self.render_result(result)

    def render_result(self, result: DetectionResult) -> None:
        color = LEVEL_COLORS.get(result.level, TEXT)
        self.level_var.set(result.level)
        self.score_var.set(f"위험 점수 {result.score}점")
        self.draw_score_bar(result.score, color)

        for item in self.url_tree.get_children():
            self.url_tree.delete(item)
        if result.urls:
            for finding in result.urls:
                notes = ", ".join(finding.notes) if finding.notes else "특이사항 없음"
                official = "공식" if finding.is_official else "비공식"
                self.url_tree.insert("", "end", values=(finding.domain, official, notes))
        else:
            self.url_tree.insert("", "end", values=("URL 없음", "-", "URL 기반 위험 신호 없음"))

        self.set_text(self.keyword_text, self.format_keywords(result))
        self.set_text(self.reason_text, "\n".join(f"- {reason}" for reason in result.reasons))

    def draw_score_bar(self, score: int = 0, color: str = SAFE) -> None:
        self.score_canvas.delete("all")
        width = max(self.score_canvas.winfo_width(), 1)
        height = max(self.score_canvas.winfo_height(), 1)
        self.score_canvas.create_rectangle(0, 0, width, height, fill="#E5E7EB", outline="")
        ratio = min(score, 20) / 20
        self.score_canvas.create_rectangle(0, 0, int(width * ratio), height, fill=color, outline="")

    def format_keywords(self, result: DetectionResult) -> str:
        if not result.keywords:
            return "탐지된 위험 키워드 없음"
        lines = []
        for category, words in result.keywords.items():
            lines.append(f"{category}: {', '.join(words)}")
        return "\n".join(lines)

    def set_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def clear_input(self) -> None:
        self.message_text.delete("1.0", "end")
        self.sender_entry.delete(0, "end")
        self.last_result = None
        self.level_var.set("검사 전")
        self.score_var.set("0점")
        self.draw_score_bar()
        for item in self.url_tree.get_children():
            self.url_tree.delete(item)
        self.set_text(self.keyword_text, "")
        self.set_text(self.reason_text, "")

    def copy_result(self) -> None:
        if not self.last_result:
            messagebox.showinfo("복사할 결과 없음", "먼저 문자를 검사하세요.")
            return
        result = self.last_result
        text = [
            f"판정: {result.level}",
            f"점수: {result.score}점",
            "",
            "판단 근거:",
            *[f"- {reason}" for reason in result.reasons],
        ]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(text))
        messagebox.showinfo("복사 완료", "검사 결과를 클립보드에 복사했습니다.")


def main() -> None:
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
