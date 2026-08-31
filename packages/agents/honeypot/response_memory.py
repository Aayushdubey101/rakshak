import logging
from typing import List, Dict
from collections import deque
import difflib

logger = logging.getLogger("uvicorn")

class ResponseMemory:
    """
    Prevents repetitive responses by tracking recent agent outputs.
    Uses semantic similarity to detect near-duplicate responses.
    """
    
    def __init__(self, max_history: int = 5):
        self.max_history = max_history
        self.memory: Dict[str, deque] = {}  # sessionId -> deque of recent responses
    
    def add_response(self, session_id: str, response: str):
        """Store a response in memory."""
        if session_id not in self.memory:
            self.memory[session_id] = deque(maxlen=self.max_history)
        
        normalized = response.lower().strip()
        self.memory[session_id].append(normalized)
    
    def is_too_similar(self, session_id: str, candidate: str, threshold: float = 0.75) -> bool:
        """
        Check if candidate response is too similar to recent responses.
        
        Args:
            session_id: Current session
            candidate: New response to check
            threshold: Similarity threshold (0.0-1.0, higher = stricter)
        
        Returns:
            True if candidate is too similar to recent responses
        """
        if session_id not in self.memory or not self.memory[session_id]:
            return False
        
        candidate_normalized = candidate.lower().strip()
        
        for past_response in self.memory[session_id]:
            similarity = difflib.SequenceMatcher(
                None, 
                candidate_normalized, 
                past_response
            ).ratio()
            
            if similarity >= threshold:
                logger.warning(
                    f"🔁 Response too similar ({similarity:.2f}): "
                    f"'{candidate[:50]}...' vs '{past_response[:50]}...'"
                )
                return True
        
        return False
    
    def get_dissimilar_variant(
        self, 
        session_id: str, 
        candidates: List[str], 
        threshold: float = 0.75
    ) -> str:
        """
        Select the most dissimilar candidate from a list.
        
        Args:
            session_id: Current session
            candidates: List of possible responses
            threshold: Similarity threshold
        
        Returns:
            Most dissimilar candidate, or first candidate if all are similar
        """
        if not candidates:
            raise ValueError("Candidates list cannot be empty")
        
        if session_id not in self.memory or not self.memory[session_id]:
            return candidates[0]
        
        # Calculate similarity scores for each candidate
        scores = []
        for candidate in candidates:
            candidate_normalized = candidate.lower().strip()
            max_similarity = max(
                difflib.SequenceMatcher(None, candidate_normalized, past).ratio()
                for past in self.memory[session_id]
            )
            scores.append((candidate, max_similarity))
        
        # Sort by similarity (ascending = least similar first)
        scores.sort(key=lambda x: x[1])
        
        best_candidate, best_score = scores[0]
        
        if best_score >= threshold:
            logger.warning(
                f"⚠️ All candidates too similar (best: {best_score:.2f}). "
                f"Using least similar anyway."
            )
        
        return best_candidate
    
    def clear_session(self, session_id: str):
        """Clear memory for a session."""
        if session_id in self.memory:
            del self.memory[session_id]

# Global instance
response_memory = ResponseMemory(max_history=5)
