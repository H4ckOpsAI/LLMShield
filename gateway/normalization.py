import unicodedata
import re

def normalize_text(text: str) -> str:
    """
    Implements safe text normalization.
    - Unicode normalization (NFKC)
    - Lowercase
    - Whitespace normalization
    - Removes basic zero-width/control characters
    """
    if not text:
        return ""
        
    # 1. Unicode normalization
    text = unicodedata.normalize('NFKC', text)
    
    # 2. Lowercase
    text = text.lower()
    
    # 3. Remove zero-width characters and control characters
    # \u200B-\u200D (zero width), \uFEFF (BOM), \x00-\x1F (control chars except standard whitespace like \n \t)
    text = re.sub(r'[\u200b-\u200d\ufeff\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
    
    # 4. Whitespace normalization (collapse multiple spaces/newlines to single space)
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()
