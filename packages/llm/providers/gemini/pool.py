import base64
import google.generativeai as genai
import logging
import asyncio
import time
from threading import Lock
from typing import Any, List, Optional
from packages.shared.config.settings import get_settings

logger = logging.getLogger("uvicorn")
settings = get_settings()

class GeminiPool:
    def __init__(self):
        self.keys = []
        self.key_states = {}  # Track key availability
        self.lock = Lock()  # Thread-safe state management
        
        # 1. Try comma separated keys
        if settings.GEMINI_API_KEYS:
            self.keys.extend([k.strip() for k in settings.GEMINI_API_KEYS.split(",") if k.strip()])
            
        # 2. Try individual keys (1-4) - matching .env naming
        individual_keys = [
            settings.GEMINI_API_KEY1,
            settings.GEMINI_API_KEY2,
            settings.GEMINI_API_KEY3,
            settings.GEMINI_API_KEY4
        ]
        for k in individual_keys:
            if k and k.strip():
                self.keys.append(k.strip())
        
        # 3. Fallback to single legacy key if pool is empty
        if not self.keys and settings.GEMINI_API_KEY:
            self.keys.append(settings.GEMINI_API_KEY)

        # Remove duplicates while preserving order
        self.keys = list(dict.fromkeys(self.keys))
        
        # Initialize key states - all available initially
        for key in self.keys:
            self.key_states[key] = {
                "available": True,
                "failed_at": None,
                "cooldown": 300  # 5 minutes cooldown
            }
        
        if not self.keys:
            logger.warning("⚠️ No Gemini API keys found in configuration")
        else:
            logger.info(f"✅ Initialized Gemini pool with {len(self.keys)} keys")

        self.current_index = 0

    def _mark_key_failed(self, key: str):
        """Mark a key as failed with timestamp for cooldown."""
        with self.lock:
            if key in self.key_states:
                self.key_states[key]["available"] = False
                self.key_states[key]["failed_at"] = time.time()
                logger.warning(f"🔴 Key ...{key[-4:]} marked as unavailable")

    def _check_key_cooldown(self, key: str) -> bool:
        """Check if a failed key has cooled down and can be retried."""
        with self.lock:
            if key not in self.key_states:
                return False
            
            state = self.key_states[key]
            if state["available"]:
                return True
            
            # Check cooldown period
            if state["failed_at"]:
                elapsed = time.time() - state["failed_at"]
                if elapsed > state["cooldown"]:
                    # Reset key to available
                    state["available"] = True
                    state["failed_at"] = None
                    logger.info(f"🟢 Key ...{key[-4:]} cooldown expired, marking available")
                    return True
            
            return False

    def _get_next_available_key(self) -> str:
        """Get next available key using failover logic (not round-robin retry)."""
        if not self.keys:
            return None
        
        # Try each key once in order
        for _ in range(len(self.keys)):
            key = self.keys[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.keys)
            
            # Check if key is available or cooled down
            if self._check_key_cooldown(key):
                return key
        
        # All keys unavailable
        return None

    @staticmethod
    def _prepare_contents(prompt: str, images: Optional[List[Any]] = None) -> Any:
        """Builds multimodal contents list for Gemini API when images are present."""
        if not images:
            return prompt
        contents: list[Any] = []
        for img in images:
            if isinstance(img, str) and img.startswith("data:"):
                try:
                    header, b64_data = img.split(",", 1)
                    mime_type = header.split(";", 1)[0].removeprefix("data:")
                    raw_data = base64.b64decode(b64_data)
                    contents.append({"mime_type": mime_type, "data": raw_data})
                except Exception as exc:
                    logger.warning(f"Failed to decode image data URL: {exc}")
            elif isinstance(img, dict) and "mime_type" in img and "data" in img:
                contents.append(img)
            elif isinstance(img, str):
                contents.append(img)
            else:
                contents.append(img)
        contents.append(prompt)
        return contents

    async def generate_content(
        self,
        prompt: str,
        images: Optional[List[Any]] = None,
        model_id: Optional[str] = None,
    ) -> Optional[str]:
        """
        Generates content using Gemini with TRUE FAILOVER (not retry).
        Supports multimodal image inputs and customizable model_id.
        """
        if not self.keys:
            logger.error("❌ No Gemini keys available for generation")
            return None

        contents = self._prepare_contents(prompt, images)
        chosen_model = model_id or "gemini-2.0-flash"

        tried_keys = set()
        last_error = None

        # Try each available key exactly once
        while len(tried_keys) < len(self.keys):
            key = self._get_next_available_key()
            
            if not key:
                # All keys exhausted
                logger.error(f"❌ All {len(self.keys)} Gemini keys exhausted or unavailable")
                break
            
            if key in tried_keys:
                # Already tried this key in this request
                continue
            
            tried_keys.add(key)
            
            try:
                # Configure with specific key
                genai.configure(api_key=key)
                model = genai.GenerativeModel(chosen_model)
                
                response = await asyncio.wait_for(
                    model.generate_content_async(contents),
                    timeout=15.0
                )
                
                if response and response.text:
                    logger.debug(f"✅ Generated content using key ...{key[-4:]}")
                    return response.text
                return ""
                
            except asyncio.TimeoutError:
                logger.warning(f"⏱️ Gemini Key ...{key[-4:]} timed out (>15s)")
                self._mark_key_failed(key)
                last_error = "Timeout"
                
            except Exception as e:
                error_msg = str(e).lower()
                is_rate_limit = "429" in error_msg or "quota" in error_msg or "exhausted" in error_msg or "rate" in error_msg
                
                if is_rate_limit:
                    logger.warning(f"🚫 Gemini Key ...{key[-4:]} quota exceeded - marking unavailable")
                    self._mark_key_failed(key)
                else:
                    logger.warning(f"⚠️ Gemini Key ...{key[-4:]} failed: {str(e)[:100]}")
                
                last_error = e
        
        # All keys failed - trigger fallback
        logger.error(f"💥 All Gemini attempts failed - triggering fallback response")
        return None

# Global instance
gemini_pool = GeminiPool()

