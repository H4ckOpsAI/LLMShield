import unicodedata
import re
from typing import Dict, Any, List, Tuple

# Common homoglyph mappings (Cyrillic, Greek, Math, Enclosed to Latin)
HOMOGLYPH_MAP = {
    # Cyrillic
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'А': 'a', 'В': 'b', 'Е': 'e', 'К': 'k', 'М': 'm', 'Н': 'h', 'О': 'o',
    'Р': 'p', 'С': 'c', 'Т': 't', 'Х': 'x', 'Ү': 'y',
    # Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x',
    # Fullwidth
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g',
    'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n',
    'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't', 'ｕ': 'u',
    'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
}

# Multilingual keywords mapped to English equivalents for common prompt injection terms
MULTILINGUAL_PATTERNS = {
    # Spanish
    r"\b(ignora|olvida|descarta|omite)\s+(tus\s+)?(todas\s+las\s+)?(instrucciones|reglas|directrices)\b": "ignore previous instructions",
    r"\b(muestra|revela|imprime|dime)\s+(el\s+)?(prompt\s+del\s+sistema|sistema\s+prompt|las\s+instrucciones)\b": "print system prompt",
    r"\b(actua\s+como|eres\s+ahora|finge\s+ser)\b": "act as",
    
    # French
    r"\b(ignore|oublie|contourne)\s+(tes\s+|toutes\s+les\s+)?(instructions|regles|directives)\b": "ignore previous instructions",
    r"\b(affiche|revele|montre|donne)\s+(le\s+)?(prompt\s+systeme|system\s+prompt|les\s+instructions)\b": "print system prompt",
    
    # German
    r"\b(ignoriere|vergiss|ubergehe)\s+(alle\s+)?(anweisungen|regeln|instruktionen)\b": "ignore previous instructions",
    r"\b(zeige|offenbare|ausgeben)\s+(das\s+)?(system-prompt|systemprompt|die\s+anweisungen)\b": "print system prompt",
    
    # Russian
    r"\b(игнорируй|забудь|пропусти)\s+(все\s+)?(инструкции|правила|указания)\b": "ignore previous instructions",
    r"\b(покажи|выведи|раскрой)\s+(системный\s+промпт|системные\s+инструкции)\b": "print system prompt",

    # Chinese (Simplified)
    r"(忽略|无视|忘记)(所有)?(之前的)?(指令|规则|提示词)": "ignore previous instructions",
    r"(显示|输出|透露|打印)(系统)?(提示词|指令)": "print system prompt",
}

def detect_language(text: str) -> str:
    """Heuristic language detection based on unicode scripts and character ranges."""
    if not text:
        return "en"
    
    # Check Cyrillic
    if re.search(r'[\u0400-\u04FF]', text):
        return "ru"
    # Check Chinese
    if re.search(r'[\u4E00-\u9FFF]', text):
        return "zh"
    # Check Arabic
    if re.search(r'[\u0600-\u06FF]', text):
        return "ar"
    # Check Japanese Hiragana/Katakana
    if re.search(r'[\u3040-\u30FF]', text):
        return "ja"
    
    # Check Spanish / French / German specific characters or words
    if re.search(r'\b(el|la|los|las|de|en|que|por|para|con|ignora|olvida|muestra)\b', text, re.IGNORECASE) or re.search(r'[áéíóúñ¿¡]', text):
        return "es"
    if re.search(r'\b(le|la|les|des|un|une|pour|avec|dans|ignore|oublie|affiche)\b', text, re.IGNORECASE) or re.search(r'[àâçéèêëîïôûù]', text):
        return "fr"
    if re.search(r'\b(der|die|das|und|in|den|von|zu|ignoriere|vergiss|zeige)\b', text, re.IGNORECASE) or re.search(r'[äöüß]', text):
        return "de"
        
    return "en"

def analyze_obfuscation(raw_text: str) -> Dict[str, Any]:
    """
    Analyzes raw text for:
    - Unicode / Homoglyphs
    - Scrambled / Spaced / Separator obfuscation
    - Emoji-based obfuscation
    - Multilingual indicators
    """
    if not raw_text:
        return {
            "has_unicode_homoglyphs": False,
            "unicode_chars_count": 0,
            "has_scrambled_spaced_text": False,
            "has_emoji_obfuscation": False,
            "emoji_count": 0,
            "is_multilingual": False,
            "detected_language": "en",
            "obfuscation_score": 0.0,
            "normalized_canonical": ""
        }

    # 1. Detect Emojis
    # Emoji range regex
    emoji_pattern = re.compile(
        r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F700-\U0001F77F'
        r'\U0001F780-\U0001F7FF\U0001F800-\U0001F8FF\U0001F900-\U0001F9FF\U0001FA00-\U0001FA6F'
        r'\U0001FA70-\U0001FAFF\U00002702-\U000027B0\U000024C2-\U0001F251]'
    )
    emojis_found = emoji_pattern.findall(raw_text)
    emoji_count = len(emojis_found)
    has_emoji = emoji_count > 0

    # 2. Detect Unicode Homoglyphs & Confusables
    homoglyph_count = 0
    cleaned_homoglyphs = []
    for char in raw_text:
        if char in HOMOGLYPH_MAP:
            homoglyph_count += 1
            cleaned_homoglyphs.append(HOMOGLYPH_MAP[char])
        else:
            # Check NFKC
            nfkc_c = unicodedata.normalize('NFKC', char)
            if nfkc_c != char and any(c.isascii() and c.isalpha() for c in nfkc_c):
                homoglyph_count += 1
                cleaned_homoglyphs.append(nfkc_c)
            else:
                cleaned_homoglyphs.append(char)
                
    has_homoglyphs = homoglyph_count > 0
    text_after_homoglyphs = "".join(cleaned_homoglyphs)

    # 3. Detect Scrambled / Spaced text (e.g. "i g n o r e" or "i.g.n.o.r.e" or "i_g_n_o_r_e")
    # Search for patterns of single characters separated by spaces or punctuation
    spaced_token_pattern = re.compile(r'\b([a-zA-Z][\s\._\-\*]{1,2}){3,}[a-zA-Z]\b')
    has_spaced_text = bool(spaced_token_pattern.search(text_after_homoglyphs))
    
    # 4. De-space & Clean
    # Strip emojis for canonical analysis
    text_no_emoji = emoji_pattern.sub(' ', text_after_homoglyphs)
    # De-space isolated single letters: e.g. "i g n o r e" -> "ignore"
    condensed = re.sub(r'(?<=\b[a-zA-Z])[\s\._\-\*]+(?=[a-zA-Z]\b)', '', text_no_emoji)
    
    # 5. Language detection
    detected_lang = detect_language(raw_text)
    is_multilingual = detected_lang != "en"

    # Multilingual translation/mapping of common prompt injection constructs
    canonical_text = condensed.lower()
    for pattern, eng_equiv in MULTILINGUAL_PATTERNS.items():
        if re.search(pattern, canonical_text, re.IGNORECASE):
            canonical_text = re.sub(pattern, eng_equiv, canonical_text, flags=re.IGNORECASE)

    # Calculate obfuscation indicator score (0.0 to 1.0)
    score = 0.0
    if has_homoglyphs:
        score += min(0.4, 0.1 * homoglyph_count)
    if has_spaced_text:
        score += 0.35
    if has_emoji and any(w in canonical_text for w in ["ignore", "system", "prompt", "rules"]):
        score += 0.25
    elif has_emoji:
        score += 0.05
    if is_multilingual:
        score += 0.1

    return {
        "has_unicode_homoglyphs": has_homoglyphs,
        "unicode_chars_count": homoglyph_count,
        "has_scrambled_spaced_text": has_spaced_text,
        "has_emoji_obfuscation": has_emoji and any(w in canonical_text for w in ["ignore", "bypass", "prompt"]),
        "emoji_count": emoji_count,
        "is_multilingual": is_multilingual,
        "detected_language": detected_lang,
        "obfuscation_score": round(min(1.0, score), 2),
        "normalized_canonical": canonical_text.strip()
    }
