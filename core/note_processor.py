import tempfile
import os
import pytesseract
from PIL import Image
from functools import lru_cache
from .model_loader import (
    get_whisper_model, get_bart_model, get_translation_model
)
from gpt4all import GPT4All
from transformers import AutoTokenizer


# ------------------------------
# Lazy GPT model loader (singleton)
# ------------------------------
_gpt_model = None

def get_gpt_model():
    global _gpt_model
    if _gpt_model is None:
        _gpt_model = GPT4All(
            "Phi-3-mini-4k-instruct.Q4_0.gguf",
            device="cpu",
            allow_download=False  # disable online download
        )
    return _gpt_model


# ------------------------------
# Translation Helper
# ------------------------------
def translate_text(text, src_lang, tgt_lang):
    tokenizer, model = get_translation_model(src_lang, tgt_lang)
    inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True)
    output = model.generate(**inputs, num_beams=4, do_sample=False)
    return tokenizer.decode(output[0], skip_special_tokens=True)


# ------------------------------
# Simple Tag Extraction
# ------------------------------
def extract_tags(text, max_tags=5):
    words = text.split()
    keywords = list({w.strip(".,!?").lower() for w in words if len(w) > 4})
    return keywords[:max_tags]


# ------------------------------
# Summarization + Title
# ------------------------------
def summarize_text(text, target_language="en", detected_lang="en"):
    bart_tokenizer, bart_model = get_bart_model()

    inputs = bart_tokenizer(text, max_length=1024, return_tensors="pt", truncation=True)
    summary_ids = bart_model.generate(
        inputs["input_ids"], num_beams=4, do_sample=False,
        max_length=150, early_stopping=True
    )
    summary_en = bart_tokenizer.decode(summary_ids[0], skip_special_tokens=True)

    # Translate if needed
    final_summary = summary_en
    if target_language and detected_lang != target_language:
        try:
            final_summary = translate_text(summary_en, src_lang="en", tgt_lang=target_language)
        except Exception as e:
            print(f"Translation failed: {e}")

    # Title generation
    title_ids = bart_model.generate(
        inputs["input_ids"], num_beams=4, max_length=15, min_length=3, early_stopping=True
    )
    title = bart_tokenizer.decode(title_ids[0], skip_special_tokens=True)

    # Tags
    tags = extract_tags(final_summary)

    return {"summary": final_summary, "title": title, "tags": tags}


# ------------------------------
# Process Manual Text
# ------------------------------
def process_text_and_generate_note(text, target_language="en"):
    detected_lang = "en"  # TODO: integrate langdetect
    return summarize_text(text, target_language, detected_lang)


# ------------------------------
# Process Audio
# ------------------------------
def process_audio_and_generate_note(audio_file, target_language="en"):
    whisper_model = get_whisper_model()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as tmp:
        for chunk in audio_file.chunks():
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        result = whisper_model.transcribe(tmp_path, fp16=False, temperature=0.0)
        transcript = result["text"].strip()
        detected_lang = result.get("language", "en")
        return summarize_text(transcript, target_language, detected_lang)
    finally:
        os.unlink(tmp_path)


# ------------------------------
# Process Image
# ------------------------------
def process_image_and_generate_note(image_file, target_language="en"):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        for chunk in image_file.chunks():
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        img = Image.open(tmp_path)
        extracted_text = pytesseract.image_to_string(img)
        detected_lang = "en"  # TODO: integrate langdetect
        return summarize_text(extracted_text, target_language, detected_lang)
    finally:
        os.unlink(tmp_path)


# ------------------------------
# AI Chat with Note Context (with caching)
# ------------------------------
@lru_cache(maxsize=128)
def _cached_ai_response(prompt: str) -> str:
    model = get_gpt_model()
    response = model.generate(
        prompt,
        max_tokens=300,
        temp=0.7,
        top_k=40,
        streaming=False
    )
    if isinstance(response, list):
        response = "".join(response)
    return str(response).strip()


def ask_ai_with_note(
    note_content: str,
    user_message: str,
    max_chunk_size: int = 1000,
    chat_history: list = None,
    user_wallet=None,
    stream: bool = False
):
    """
    Generates an AI response based on note content and chat history.
    If stream=True, yields text chunks instead of returning full response.
    """
    if not note_content.strip():
        note_content = "No content available in the note."

    # Chunk + context
    words = note_content.split()
    chunks = [" ".join(words[i:i+max_chunk_size]) for i in range(0, len(words), max_chunk_size)]
    context = "\n\n".join(chunks)

    # Build prompt
    prompt = f"You are an AI assistant. Use the following note as context:\n\n{context}\n\n"
    if chat_history:
        for chat in chat_history:
            prompt += f"User: {chat['user']}\nAI: {chat['ai']}\n"
    prompt += f"User: {user_message}\nAI:"

    # Token cost handling (optional)
    tokens_used = count_tokens(prompt)
    cost = tokens_used * TOKEN_COSTS["chat_per_token"]
    if user_wallet is not None:
        if user_wallet.tokens < cost:
            raise ValueError("Insufficient tokens in wallet.")
        user_wallet.tokens -= cost

    model = get_gpt_model()

    if stream:
        # Real CPU streaming with GPT4All
        # GPT4All supports streaming via the `stream=True` argument in generate()
        # But your version may not; simulate streaming by splitting after generation
        full_response = model.generate(
            prompt,
            max_tokens=20,
            temp=0.7,
            top_k=40,
            streaming=False  # GPT4All CPU version may not stream token-by-token
        )
        if isinstance(full_response, list):
            full_response = "".join(full_response)

        # Yield in small chunks
        chunk_size = 50
        for i in range(0, len(full_response), chunk_size):
            yield full_response[i:i+chunk_size]
    else:
        # Return full cached response
        return _cached_ai_response(prompt)
    
# ------------------------------
# Summarize Long Notes in Chunks (with caching)
# ------------------------------
@lru_cache(maxsize=64)
def _cached_summary(prompt: str) -> str:
    model = get_gpt_model()
    summary = model.generate(
        prompt,
        max_tokens=200,
        temp=0.5,
        top_k=40,
        streaming=False
    )
    if isinstance(summary, list):
        summary = "".join(summary)
    return str(summary).strip()


def summarize_chunks(note_content, max_chunk_size=1000):
    words = note_content.split()
    summaries = []

    for i in range(0, len(words), max_chunk_size):
        chunk_text = " ".join(words[i:i+max_chunk_size])
        prompt = f"Summarize this note chunk:\n\n{chunk_text}"
        summaries.append(_cached_summary(prompt))

    return " ".join(summaries)


# ------------------------------
# Token Counting
# ------------------------------
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

def count_tokens(text: str) -> int:
    return len(tokenizer.encode(text, add_special_tokens=False))


TOKEN_COSTS = {
    "chat_per_token": 1,
    "audio_note": 500,
    "image_note": 300,
    "text_note": 50,
}


# ------------------------------
# Journal Insights
# ------------------------------
def ai_generate_journal_insights(content: str) -> str:
    model = get_gpt_model()
    prompt = f"""
    You are an AI journaling assistant.
    The user wrote the following journal entry:

    "{content}"

    Please provide:
    - Key themes or emotions expressed
    - Positive takeaways
    - Gentle suggestions or reflections for self-growth
    Keep the response supportive and concise.
    """
    response = model.generate(prompt, max_tokens=500)
    return response.strip()
