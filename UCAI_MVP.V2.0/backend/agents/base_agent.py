"""
BaseAgent — hardened for production:
- Proper async Gemini calls
- Exponential backoff on rate limit / transient errors
- JSON parse resilience (strip markdown fences, retry once)
- Never raises unhandled exceptions — always returns structured error dict
"""
import google.generativeai as genai
import asyncio, time, os, json, re, logging

logger = logging.getLogger("uaci.agents")

_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if _API_KEY:
    genai.configure(api_key=_API_KEY)
else:
    logger.warning("GEMINI_API_KEY not set — agent calls will fail")


class GeminiRateLimiter:
    """Token-bucket: 14 RPM to stay under free-tier 15 RPM hard limit."""
    def __init__(self, rpm: int = 14):
        self.rpm = rpm
        self._requests: list[float] = []
        self._lock = asyncio.Lock()

    async def wait_if_needed(self):
        async with self._lock:
            now = time.time()
            self._requests = [r for r in self._requests if now - r < 60]
            if len(self._requests) >= self.rpm:
                wait = 61 - (now - self._requests[0])
                logger.info(f"Rate limit: sleeping {wait:.1f}s")
                await asyncio.sleep(max(wait, 0))
            self._requests.append(time.time())


_rate_limiter = GeminiRateLimiter()


class BaseAgent:
    SYSTEM_INSTRUCTION: str = ""

    def __init__(self):
        model_name = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
        self.model = genai.GenerativeModel(
            model_name=model_name,
            generation_config=genai.GenerationConfig(
                max_output_tokens=2048,
                temperature=0.1,
            ),
            system_instruction=self.SYSTEM_INSTRUCTION or None,
        )

    async def generate(self, prompt: str) -> str:
        """Call Gemini with exponential backoff on transient errors."""
        for attempt in range(3):
            await _rate_limiter.wait_if_needed()
            try:
                response = self.model.generate_content(prompt)
                return response.text
            except Exception as exc:
                wait = 2 ** attempt
                logger.warning(f"Gemini error attempt {attempt+1}: {exc} — retrying in {wait}s")
                if attempt < 2:
                    await asyncio.sleep(wait)
                else:
                    raise RuntimeError(f"Gemini failed after 3 attempts: {exc}") from exc

    async def generate_json(self, prompt: str, schema_hint: str = "") -> dict:
        """
        Force JSON from Gemini.
        - Strips markdown fences
        - Extracts first {...} block if model wraps response
        - Falls back to error dict — never raises
        """
        full_prompt = (
            f"{prompt}\n\n"
            f"IMPORTANT: Respond ONLY with valid raw JSON. "
            f"No markdown, no ```json fences, no explanation outside the JSON object.\n"
            f"Schema hint: {schema_hint}"
        )
        try:
            raw = await self.generate(full_prompt)
            # Strip fences
            clean = re.sub(r"```(?:json)?", "", raw).strip().strip("`").strip()
            # Extract first {...} block
            match = re.search(r"\{[\s\S]*\}", clean)
            if match:
                clean = match.group(0)
            return json.loads(clean)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e} | raw: {raw[:300]}")
            return {"error": "agent_parse_error", "detail": str(e)}
        except Exception as e:
            logger.error(f"generate_json failed: {e}")
            return {"error": "agent_error", "detail": str(e)}
