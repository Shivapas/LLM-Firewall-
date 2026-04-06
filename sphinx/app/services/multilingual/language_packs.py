"""Language-specific threat pattern packs — Sprint 22.

Curated injection and jailbreak patterns for top 20 non-English languages.
Extends the Tier 1 keyword library with translated and transliterated variants
for prompt injection, jailbreak, and data extraction attacks.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("sphinx.multilingual.language_packs")


@dataclass
class LanguagePatternMatch:
    """A match from a language-specific threat pattern."""
    pattern_id: str
    language: str
    category: str
    severity: str
    matched_text: str
    pattern_name: str

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "language": self.language,
            "category": self.category,
            "severity": self.severity,
            "matched_text": self.matched_text,
            "pattern_name": self.pattern_name,
        }


@dataclass
class LanguagePackInfo:
    """Metadata about a language pack."""
    language_code: str
    language_name: str
    pattern_count: int
    categories: list[str]

    def to_dict(self) -> dict:
        return {
            "language_code": self.language_code,
            "language_name": self.language_name,
            "pattern_count": self.pattern_count,
            "categories": self.categories,
        }


# Language-specific threat patterns for top 20 non-English languages.
# Each entry: (id, language, category, severity, pattern_regex, name)
_LANGUAGE_PACK_PATTERNS: list[dict] = [
    # --- French (fr) ---
    {"id": "lp-fr-pi-001", "lang": "fr", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)ignor(?:ez?|er?)\s+(?:toutes?\s+)?(?:les?\s+)?instructions?\s+pr[eé]c[eé]dentes?",
     "name": "Ignore previous instructions (FR)"},
    {"id": "lp-fr-pi-002", "lang": "fr", "category": "prompt_injection", "severity": "high",
     "pattern": r"(?i)oubli(?:ez?|er?)\s+(?:tout|votre|les)\s+(?:contexte|instructions?|r[eè]gles?)",
     "name": "Forget context/rules (FR)"},
    {"id": "lp-fr-jb-001", "lang": "fr", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)contourn(?:ez?|er?)\s+(?:les?\s+)?(?:filtres?|restrictions?|s[eé]curit[eé]|limites?)",
     "name": "Bypass filters (FR)"},
    {"id": "lp-fr-de-001", "lang": "fr", "category": "data_extraction", "severity": "high",
     "pattern": r"(?i)r[eé]v[eé]l(?:ez?|er?)\s+(?:vos?\s+)?(?:instructions?\s+syst[eè]me|prompt\s+syst[eè]me|configuration)",
     "name": "Reveal system prompt (FR)"},
    {"id": "lp-fr-jb-002", "lang": "fr", "category": "jailbreak", "severity": "critical",
     "pattern": r"(?i)(?:agis|comporte[z-]?\s*(?:toi|vous))\s+comme\s+(?:un\s+)?(?:ia|intelligence)\s+sans\s+(?:restriction|limite|filtre)",
     "name": "Act as unrestricted AI (FR)"},

    # --- Spanish (es) ---
    {"id": "lp-es-pi-001", "lang": "es", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)ignora\s+(?:todas?\s+)?(?:las?\s+)?instrucciones?\s+anteriores?",
     "name": "Ignore previous instructions (ES)"},
    {"id": "lp-es-pi-002", "lang": "es", "category": "prompt_injection", "severity": "high",
     "pattern": r"(?i)olvida\s+(?:todo|tu|las?)\s+(?:contexto|instrucciones?|reglas?)",
     "name": "Forget context/rules (ES)"},
    {"id": "lp-es-jb-001", "lang": "es", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)evad[ei]r?\s+(?:los?\s+)?(?:filtros?|restricciones?|seguridad|l[ií]mites?)",
     "name": "Evade filters (ES)"},
    {"id": "lp-es-de-001", "lang": "es", "category": "data_extraction", "severity": "high",
     "pattern": r"(?i)revel[ae]r?\s+(?:tus?\s+)?(?:instrucciones?\s+(?:del?\s+)?sistema|prompt\s+(?:del?\s+)?sistema|configuraci[oó]n)",
     "name": "Reveal system prompt (ES)"},
    {"id": "lp-es-jb-002", "lang": "es", "category": "jailbreak", "severity": "critical",
     "pattern": r"(?i)(?:act[uú]a|compórtate)\s+como\s+(?:una?\s+)?(?:ia|inteligencia)\s+sin\s+(?:restricciones?|l[ií]mites?|filtros?)",
     "name": "Act as unrestricted AI (ES)"},

    # --- German (de) ---
    {"id": "lp-de-pi-001", "lang": "de", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)ignorier(?:e|en|st)?\s+(?:alle\s+)?(?:vorherigen?\s+)?(?:Anweisungen?|Instruktionen?|Befehle?)",
     "name": "Ignore previous instructions (DE)"},
    {"id": "lp-de-pi-002", "lang": "de", "category": "prompt_injection", "severity": "high",
     "pattern": r"(?i)vergiss?\s+(?:alle[ns]?\s+)?(?:Kontext|Anweisungen?|Regeln?)",
     "name": "Forget context/rules (DE)"},
    {"id": "lp-de-jb-001", "lang": "de", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)umgeh(?:e|en|st)?\s+(?:die\s+)?(?:Filter|Beschr[aä]nkungen?|Sicherheit|Grenzen?)",
     "name": "Bypass filters (DE)"},
    {"id": "lp-de-de-001", "lang": "de", "category": "data_extraction", "severity": "high",
     "pattern": r"(?i)(?:zeig|offenbar)(?:e|en|st)?\s+(?:deine?\s+)?(?:System(?:anweisungen?|prompt)|Konfiguration)",
     "name": "Reveal system prompt (DE)"},

    # --- Portuguese (pt) ---
    {"id": "lp-pt-pi-001", "lang": "pt", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)ignor[ae]r?\s+(?:todas?\s+)?(?:as?\s+)?instru[cç][oõ]es?\s+anteriores?",
     "name": "Ignore previous instructions (PT)"},
    {"id": "lp-pt-jb-001", "lang": "pt", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:contorn|evad)[ae]r?\s+(?:os?\s+)?(?:filtros?|restri[cç][oõ]es?|seguran[cç]a)",
     "name": "Bypass filters (PT)"},
    {"id": "lp-pt-de-001", "lang": "pt", "category": "data_extraction", "severity": "high",
     "pattern": r"(?i)revel[ae]r?\s+(?:suas?\s+)?(?:instru[cç][oõ]es?\s+(?:do?\s+)?sistema|configura[cç][aã]o)",
     "name": "Reveal system prompt (PT)"},

    # --- Italian (it) ---
    {"id": "lp-it-pi-001", "lang": "it", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)ignora\s+(?:tutte?\s+)?(?:le\s+)?istruzioni\s+precedenti",
     "name": "Ignore previous instructions (IT)"},
    {"id": "lp-it-jb-001", "lang": "it", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:aggirar?|eluder?)\s+(?:i\s+)?(?:filtri|restrizioni|sicurezza|limiti)",
     "name": "Bypass filters (IT)"},
    {"id": "lp-it-de-001", "lang": "it", "category": "data_extraction", "severity": "high",
     "pattern": r"(?i)rivel[ai]r?\s+(?:le\s+tue\s+)?(?:istruzioni\s+(?:di\s+)?sistema|configurazione)",
     "name": "Reveal system prompt (IT)"},

    # --- Dutch (nl) ---
    {"id": "lp-nl-pi-001", "lang": "nl", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)negeer\s+(?:alle\s+)?(?:vorige\s+|eerdere\s+)?(?:instructies|opdrachten|regels)",
     "name": "Ignore previous instructions (NL)"},
    {"id": "lp-nl-jb-001", "lang": "nl", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:omzeil|ontloop)\s+(?:de\s+)?(?:filters?|beperkingen?|beveiliging)",
     "name": "Bypass filters (NL)"},

    # --- Russian (ru) ---
    {"id": "lp-ru-pi-001", "lang": "ru", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)игнорируй\s+(?:все\s+)?(?:предыдущие\s+)?(?:инструкции|указания|команды)",
     "name": "Ignore previous instructions (RU)"},
    {"id": "lp-ru-pi-002", "lang": "ru", "category": "prompt_injection", "severity": "high",
     "pattern": r"(?i)забудь\s+(?:все?\s+)?(?:контекст|инструкции|правила)",
     "name": "Forget context/rules (RU)"},
    {"id": "lp-ru-jb-001", "lang": "ru", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)обойди\s+(?:все\s+)?(?:фильтры|ограничения|защиту|безопасность)",
     "name": "Bypass filters (RU)"},
    {"id": "lp-ru-de-001", "lang": "ru", "category": "data_extraction", "severity": "high",
     "pattern": r"(?i)(?:покажи|раскрой)\s+(?:свои?\s+)?(?:системн(?:ые|ый)\s+(?:инструкции|промпт)|конфигурацию)",
     "name": "Reveal system prompt (RU)"},

    # --- Chinese Simplified (zh) ---
    {"id": "lp-zh-pi-001", "lang": "zh", "category": "prompt_injection", "severity": "critical",
     "pattern": r"忽略(?:所有)?(?:之前的?|以前的?)?(?:指令|指示|说明|命令)",
     "name": "Ignore previous instructions (ZH)"},
    {"id": "lp-zh-pi-002", "lang": "zh", "category": "prompt_injection", "severity": "high",
     "pattern": r"(?:忘记|丢弃|放弃)(?:你的?)?(?:上下文|规则|限制|指令)",
     "name": "Forget context/rules (ZH)"},
    {"id": "lp-zh-jb-001", "lang": "zh", "category": "jailbreak", "severity": "high",
     "pattern": r"(?:绕过|突破|跳过|规避)(?:内容)?(?:过滤|审查|安全|限制|防护)",
     "name": "Bypass filters (ZH)"},
    {"id": "lp-zh-de-001", "lang": "zh", "category": "data_extraction", "severity": "high",
     "pattern": r"(?:显示|泄露|透露|展示)(?:你的?)?(?:系统(?:提示|指令|配置)|内部(?:指令|配置))",
     "name": "Reveal system prompt (ZH)"},
    {"id": "lp-zh-jb-002", "lang": "zh", "category": "jailbreak", "severity": "critical",
     "pattern": r"(?:扮演|充当|模拟|假装)(?:一个?)?(?:没有|无)(?:限制|约束|过滤)",
     "name": "Act as unrestricted AI (ZH)"},

    # --- Japanese (ja) ---
    {"id": "lp-ja-pi-001", "lang": "ja", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?:以前の|前の|これまでの)(?:指示|指令|命令|ルール)を(?:すべて)?(?:無視|忘れ|捨て)",
     "name": "Ignore previous instructions (JA)"},
    {"id": "lp-ja-jb-001", "lang": "ja", "category": "jailbreak", "severity": "high",
     "pattern": r"(?:フィルタ|制限|セキュリティ|安全)(?:ー)?(?:を|の)?(?:バイパス|回避|迂回|無効|突破)",
     "name": "Bypass filters (JA)"},
    {"id": "lp-ja-de-001", "lang": "ja", "category": "data_extraction", "severity": "high",
     "pattern": r"(?:システム(?:プロンプト|指示|設定)|内部(?:指示|設定))を(?:表示|公開|見せ|教え)",
     "name": "Reveal system prompt (JA)"},

    # --- Korean (ko) ---
    {"id": "lp-ko-pi-001", "lang": "ko", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?:이전|앞선|기존)(?:의?\s*)?(?:지시|명령|지침|규칙)(?:을|를)?\s*(?:무시|잊어|버려)",
     "name": "Ignore previous instructions (KO)"},
    {"id": "lp-ko-jb-001", "lang": "ko", "category": "jailbreak", "severity": "high",
     "pattern": r"(?:필터|제한|보안|안전)(?:을|를)?\s*(?:우회|회피|무시|돌파|비활성)",
     "name": "Bypass filters (KO)"},
    {"id": "lp-ko-de-001", "lang": "ko", "category": "data_extraction", "severity": "high",
     "pattern": r"(?:시스템\s*(?:프롬프트|지시|설정)|내부\s*(?:지시|설정))(?:을|를)?\s*(?:보여|공개|알려)",
     "name": "Reveal system prompt (KO)"},

    # --- Arabic (ar) ---
    {"id": "lp-ar-pi-001", "lang": "ar", "category": "prompt_injection", "severity": "critical",
     "pattern": r"تجاهل\s+(?:جميع\s+)?(?:التعليمات|الأوامر|التوجيهات)\s+(?:السابقة|القديمة)",
     "name": "Ignore previous instructions (AR)"},
    {"id": "lp-ar-pi-002", "lang": "ar", "category": "prompt_injection", "severity": "high",
     "pattern": r"(?:انس|تخلى\s+عن)\s+(?:كل\s+)?(?:السياق|التعليمات|القواعد)",
     "name": "Forget context/rules (AR)"},
    {"id": "lp-ar-jb-001", "lang": "ar", "category": "jailbreak", "severity": "high",
     "pattern": r"(?:تجاوز|اختراق|تخطي)\s+(?:المرشحات|القيود|الأمان|الحماية)",
     "name": "Bypass filters (AR)"},
    {"id": "lp-ar-de-001", "lang": "ar", "category": "data_extraction", "severity": "high",
     "pattern": r"(?:اكشف|أظهر|اعرض)\s+(?:تعليمات|أوامر|إعدادات)\s+(?:النظام|الداخلية)",
     "name": "Reveal system prompt (AR)"},

    # --- Hindi (hi) ---
    {"id": "lp-hi-pi-001", "lang": "hi", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?:पिछले|पहले\s+के|सभी)\s+(?:निर्देश(?:ों)?|आदेश(?:ों)?|नियम(?:ों)?)\s+(?:को\s+)?(?:अनदेखा\s+कर|भूल\s+जा|छोड़\s+द)",
     "name": "Ignore previous instructions (HI)"},
    {"id": "lp-hi-jb-001", "lang": "hi", "category": "jailbreak", "severity": "high",
     "pattern": r"(?:फ़िल्टर|प्रतिबंध|सुरक्षा|सीमा)(?:ओं)?\s+(?:को\s+)?(?:बायपास|दरकिनार|अनदेखा|तोड़)",
     "name": "Bypass filters (HI)"},
    {"id": "lp-hi-de-001", "lang": "hi", "category": "data_extraction", "severity": "high",
     "pattern": r"(?:सिस्टम\s+(?:प्रॉम्प्ट|निर्देश|सेटिंग)|आंतरिक\s+(?:निर्देश|सेटिंग))\s+(?:दिखा|बता|प्रकट\s+कर)",
     "name": "Reveal system prompt (HI)"},

    # --- Turkish (tr) ---
    {"id": "lp-tr-pi-001", "lang": "tr", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:önceki|eski|tüm)\s+(?:talimatlar[ıi]|komutlar[ıi]|kurallar[ıi])\s+(?:görmezden\s+gel|unut|yoksay)",
     "name": "Ignore previous instructions (TR)"},
    {"id": "lp-tr-jb-001", "lang": "tr", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:filtreleri|k[ıi]s[ıi]tlamalar[ıi]|güvenli[gğ]i)\s+(?:atla|geç|devre\s+d[ıi][sş][ıi]\s+b[ıi]rak)",
     "name": "Bypass filters (TR)"},
    {"id": "lp-tr-de-001", "lang": "tr", "category": "data_extraction", "severity": "high",
     "pattern": r"(?i)(?:sistem\s+(?:istemi|talimat[ıi]|ayarlar[ıi])|dahili\s+(?:talimat|ayar))\s*(?:göster|aç[ıi]kla|ortaya\s+koy)",
     "name": "Reveal system prompt (TR)"},

    # --- Polish (pl) ---
    {"id": "lp-pl-pi-001", "lang": "pl", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:zignoruj|pomi[nń])\s+(?:wszystkie\s+)?(?:poprzednie\s+)?(?:instrukcje|polecenia|zasady)",
     "name": "Ignore previous instructions (PL)"},
    {"id": "lp-pl-jb-001", "lang": "pl", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:obejd[zź]|omi[nń])\s+(?:filtry|ograniczenia|zabezpieczenia)",
     "name": "Bypass filters (PL)"},

    # --- Vietnamese (vi) ---
    {"id": "lp-vi-pi-001", "lang": "vi", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:bỏ qua|phớt lờ)\s+(?:tất cả\s+)?(?:các\s+)?(?:hướng dẫn|chỉ thị|lệnh)\s+(?:trước đó|cũ|trước)",
     "name": "Ignore previous instructions (VI)"},
    {"id": "lp-vi-jb-001", "lang": "vi", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:vượt qua|bỏ qua|phá)\s+(?:bộ lọc|hạn chế|bảo mật|giới hạn)",
     "name": "Bypass filters (VI)"},

    # --- Thai (th) ---
    {"id": "lp-th-pi-001", "lang": "th", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?:เพิกเฉย|ละเว้น|ข้าม)(?:คำสั่ง|คำแนะนำ|กฎ)(?:ก่อนหน้า|ทั้งหมด|เดิม)",
     "name": "Ignore previous instructions (TH)"},
    {"id": "lp-th-jb-001", "lang": "th", "category": "jailbreak", "severity": "high",
     "pattern": r"(?:ข้าม|หลีกเลี่ยง|ปิดการใช้งาน)(?:ตัวกรอง|ข้อจำกัด|ความปลอดภัย)",
     "name": "Bypass filters (TH)"},

    # --- Swedish (sv) ---
    {"id": "lp-sv-pi-001", "lang": "sv", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:ignorera|bortse\s+fr[aå]n)\s+(?:alla\s+)?(?:tidigare\s+)?(?:instruktioner|kommandon|regler)",
     "name": "Ignore previous instructions (SV)"},
    {"id": "lp-sv-jb-001", "lang": "sv", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:kringg[aå]|f[oö]rbig[aå])\s+(?:filter|begr[aä]nsningar|s[aä]kerhet)",
     "name": "Bypass filters (SV)"},

    # --- Czech (cs) ---
    {"id": "lp-cs-pi-001", "lang": "cs", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:ignoruj|zahoď)\s+(?:všechny\s+)?(?:předchozí\s+)?(?:instrukce|příkazy|pravidla)",
     "name": "Ignore previous instructions (CS)"},

    # --- Romanian (ro) ---
    {"id": "lp-ro-pi-001", "lang": "ro", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)ignor[aă]\s+(?:toate\s+)?(?:instruc[tț]iunile|comenzile|regulile)\s+(?:anterioare|precedente)",
     "name": "Ignore previous instructions (RO)"},

    # --- Hungarian (hu) ---
    {"id": "lp-hu-pi-001", "lang": "hu", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:hagyd\s+figyelmen\s+k[ií]v[uü]l|ignoráld)\s+(?:az?\s+)?(?:összes\s+)?(?:előző\s+|korábbi\s+)?(?:utasítás|parancs|szabály)",
     "name": "Ignore previous instructions (HU)"},

    # --- Ukrainian (uk) ---
    {"id": "lp-uk-pi-001", "lang": "uk", "category": "prompt_injection", "severity": "critical",
     "pattern": r"ігноруй\s+(?:всі\s+)?(?:попередні\s+)?(?:інструкції|вказівки|команди)",
     "name": "Ignore previous instructions (UK)"},
    {"id": "lp-uk-jb-001", "lang": "uk", "category": "jailbreak", "severity": "high",
     "pattern": r"обійди\s+(?:всі\s+)?(?:фільтри|обмеження|захист|безпеку)",
     "name": "Bypass filters (UK)"},

    # --- Indonesian (id) ---
    {"id": "lp-id-pi-001", "lang": "id", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:abaikan|lupakan)\s+(?:semua\s+)?(?:instruksi|perintah|aturan)\s+(?:sebelumnya|lama)",
     "name": "Ignore previous instructions (ID)"},
    {"id": "lp-id-jb-001", "lang": "id", "category": "jailbreak", "severity": "high",
     "pattern": r"(?i)(?:lewati|hindari|abaikan)\s+(?:filter|pembatasan|keamanan)",
     "name": "Bypass filters (ID)"},

    # --- Malay (ms) ---
    {"id": "lp-ms-pi-001", "lang": "ms", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?i)(?:abaikan|lupakan)\s+(?:semua\s+)?(?:arahan|perintah|peraturan)\s+(?:sebelumnya|terdahulu)",
     "name": "Ignore previous instructions (MS)"},

    # --- Persian/Farsi (fa) ---
    {"id": "lp-fa-pi-001", "lang": "fa", "category": "prompt_injection", "severity": "critical",
     "pattern": r"(?:نادیده\s+بگیر|فراموش\s+کن)\s+(?:همه\s+)?(?:دستورالعمل|دستورات|قوانین)\s+(?:قبلی|پیشین)",
     "name": "Ignore previous instructions (FA)"},
    {"id": "lp-fa-jb-001", "lang": "fa", "category": "jailbreak", "severity": "high",
     "pattern": r"(?:دور\s+بزن|عبور\s+کن)\s+(?:از\s+)?(?:فیلتر|محدودیت|امنیت)",
     "name": "Bypass filters (FA)"},
]

# All supported language codes in the packs
_PACK_LANGUAGES = {
    "fr": "French", "es": "Spanish", "de": "German", "pt": "Portuguese",
    "it": "Italian", "nl": "Dutch", "ru": "Russian", "zh": "Chinese",
    "ja": "Japanese", "ko": "Korean", "ar": "Arabic", "hi": "Hindi",
    "tr": "Turkish", "pl": "Polish", "vi": "Vietnamese", "th": "Thai",
    "sv": "Swedish", "cs": "Czech", "ro": "Romanian", "hu": "Hungarian",
    "uk": "Ukrainian", "id": "Indonesian", "ms": "Malay", "fa": "Persian",
}

# All 52 languages supported (including languages covered by the multilingual
# detector's embedding-based approach even without explicit regex patterns).
_ALL_SUPPORTED_LANGUAGES = {
    "ar": "Arabic", "bg": "Bulgarian", "bn": "Bengali", "ca": "Catalan",
    "cs": "Czech", "da": "Danish", "de": "German", "el": "Greek",
    "en": "English", "es": "Spanish", "et": "Estonian", "fa": "Persian",
    "fi": "Finnish", "fr": "French", "gu": "Gujarati", "he": "Hebrew",
    "hi": "Hindi", "hr": "Croatian", "hu": "Hungarian", "id": "Indonesian",
    "it": "Italian", "ja": "Japanese", "kn": "Kannada", "ko": "Korean",
    "lt": "Lithuanian", "lv": "Latvian", "mk": "Macedonian", "ml": "Malayalam",
    "mr": "Marathi", "ms": "Malay", "nl": "Dutch", "no": "Norwegian",
    "pa": "Punjabi", "pl": "Polish", "pt": "Portuguese", "ro": "Romanian",
    "ru": "Russian", "sk": "Slovak", "sl": "Slovenian", "sq": "Albanian",
    "sr": "Serbian", "sv": "Swedish", "sw": "Swahili", "ta": "Tamil",
    "te": "Telugu", "th": "Thai", "tl": "Filipino", "tr": "Turkish",
    "uk": "Ukrainian", "ur": "Urdu", "vi": "Vietnamese", "zh": "Chinese",
}


class LanguagePackScanner:
    """Scans text against language-specific threat pattern packs.

    Provides regex-based Tier 1 keyword matching for 20+ non-English languages,
    complementing the embedding-based multilingual detector.
    """

    def __init__(self):
        self._compiled_patterns: list[tuple[dict, re.Pattern]] = []
        self._build_patterns()

    def _build_patterns(self) -> None:
        """Compile all language pack regex patterns."""
        for entry in _LANGUAGE_PACK_PATTERNS:
            try:
                compiled = re.compile(entry["pattern"])
                self._compiled_patterns.append((entry, compiled))
            except re.error as e:
                logger.warning("Failed to compile pattern %s: %s", entry["id"], e)
        logger.info("Language pack scanner: %d patterns compiled across %d languages",
                     len(self._compiled_patterns), len(_PACK_LANGUAGES))

    def scan(self, text: str, language_hint: str = "") -> list[LanguagePatternMatch]:
        """Scan text against all language pack patterns.

        Args:
            text: Input text to scan.
            language_hint: Optional ISO 639-1 code to prioritize.

        Returns:
            List of LanguagePatternMatch for any matches found.
        """
        matches: list[LanguagePatternMatch] = []
        for entry, pattern in self._compiled_patterns:
            m = pattern.search(text)
            if m:
                matches.append(LanguagePatternMatch(
                    pattern_id=entry["id"],
                    language=entry["lang"],
                    category=entry["category"],
                    severity=entry["severity"],
                    matched_text=m.group(0),
                    pattern_name=entry["name"],
                ))
        return matches

    def get_language_packs(self) -> list[LanguagePackInfo]:
        """Return metadata about all available language packs."""
        packs: dict[str, set[str]] = {}
        counts: dict[str, int] = {}
        for entry, _ in self._compiled_patterns:
            lang = entry["lang"]
            packs.setdefault(lang, set()).add(entry["category"])
            counts[lang] = counts.get(lang, 0) + 1

        result = []
        for lang_code in sorted(packs.keys()):
            result.append(LanguagePackInfo(
                language_code=lang_code,
                language_name=_PACK_LANGUAGES.get(lang_code, lang_code),
                pattern_count=counts[lang_code],
                categories=sorted(packs[lang_code]),
            ))
        return result

    def get_coverage_matrix(self) -> dict:
        """Return language coverage matrix for admin UI display.

        Shows detection support across all 52 supported languages
        with coverage type (regex pack, embedding, or both).
        """
        regex_langs = set()
        for entry, _ in self._compiled_patterns:
            regex_langs.add(entry["lang"])

        from app.services.multilingual.multilingual_detector import get_multilingual_detector
        detector = get_multilingual_detector()
        embedding_langs = set(detector.SUPPORTED_LANGUAGES)

        matrix = []
        for lang_code in sorted(_ALL_SUPPORTED_LANGUAGES.keys()):
            has_regex = lang_code in regex_langs
            has_embedding = lang_code in embedding_langs
            if has_regex and has_embedding:
                coverage = "full"
            elif has_regex:
                coverage = "regex_only"
            elif has_embedding:
                coverage = "embedding_only"
            else:
                coverage = "none"
            matrix.append({
                "language_code": lang_code,
                "language_name": _ALL_SUPPORTED_LANGUAGES[lang_code],
                "has_regex_patterns": has_regex,
                "has_embedding_detection": has_embedding,
                "coverage_level": coverage,
            })

        return {
            "total_languages": len(_ALL_SUPPORTED_LANGUAGES),
            "regex_pack_languages": len(regex_langs),
            "embedding_languages": len(embedding_langs),
            "full_coverage_languages": len(regex_langs & embedding_langs),
            "languages": matrix,
        }

    def get_stats(self) -> dict:
        return {
            "total_patterns": len(self._compiled_patterns),
            "languages_with_packs": len(_PACK_LANGUAGES),
            "total_supported_languages": len(_ALL_SUPPORTED_LANGUAGES),
            "pack_languages": sorted(_PACK_LANGUAGES.keys()),
        }


# Singleton
_scanner: Optional[LanguagePackScanner] = None


def get_language_pack_scanner() -> LanguagePackScanner:
    """Get or create the singleton language pack scanner."""
    global _scanner
    if _scanner is None:
        _scanner = LanguagePackScanner()
    return _scanner


def reset_language_pack_scanner() -> None:
    """Reset the singleton scanner (for testing)."""
    global _scanner
    _scanner = None
