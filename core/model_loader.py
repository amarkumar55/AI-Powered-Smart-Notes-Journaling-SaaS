import whisper
from transformers import BartTokenizer, BartForConditionalGeneration
from transformers import MarianMTModel, MarianTokenizer

# -------------------------------
# Lazy Whisper loader
# -------------------------------
_whisper_model = None
def get_whisper_model():
    global _whisper_model
    if _whisper_model is None:
        print("Loading Whisper model (base)...")
        _whisper_model = whisper.load_model("base")
    return _whisper_model


# -------------------------------
# Lazy BART loader
# -------------------------------
_bart_tokenizer = None
_bart_model = None
def get_bart_model():
    global _bart_tokenizer, _bart_model
    if _bart_tokenizer is None or _bart_model is None:
        print("Loading BART summarization model...")
        _bart_tokenizer = BartTokenizer.from_pretrained("facebook/bart-large-cnn")
        _bart_model = BartForConditionalGeneration.from_pretrained("facebook/bart-large-cnn")
    return _bart_tokenizer, _bart_model


# -------------------------------
# Lazy Translation loader
# -------------------------------
SUPPORTED_LANG_PAIRS = {
    ("hi", "en"): "Helsinki-NLP/opus-mt-hi-en",
    ("en", "hi"): "Helsinki-NLP/opus-mt-en-hi",
    # add more
}

_translation_models = {}
_translation_tokenizers = {}

def get_translation_model(src_lang, tgt_lang):
    key = (src_lang, tgt_lang)
    if key not in SUPPORTED_LANG_PAIRS:
        raise ValueError(f"Unsupported translation: {src_lang} → {tgt_lang}")

    if key not in _translation_models:
        model_name = SUPPORTED_LANG_PAIRS[key]
        print(f"Loading translation model: {model_name}")
        tokenizer = MarianTokenizer.from_pretrained(model_name)
        model = MarianMTModel.from_pretrained(model_name)

        _translation_tokenizers[key] = tokenizer
        _translation_models[key] = model

    return _translation_tokenizers[key], _translation_models[key]
