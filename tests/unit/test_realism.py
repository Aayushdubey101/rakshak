import pytest

from packages.agents.honeypot.emotion_engine import EmotionEngine, EmotionState
from packages.agents.honeypot.response_memory import response_memory

pytestmark = pytest.mark.characterization


def test_memory():
    """Test response memory deduplication."""
    session_id = "test-001"
    
    print("\n--- Testing Response Memory ---")
    
    # Add some responses
    response_memory.add_response(session_id, "share bank account now")
    response_memory.add_response(session_id, "send upi id pls")
    
    # Test similarity detection
    is_similar = response_memory.is_too_similar(
        session_id, 
        "share bank account urgent",  # High similarity
        threshold=0.70
    )
    print(f"Similarity check (expected True): {is_similar}")
    assert is_similar, "Failed to detect similar response"
    
    is_not_similar = response_memory.is_too_similar(
        session_id,
        "ok how do i proceed?",  # Low similarity
        threshold=0.70
    )
    print(f"Dissimilarity check (expected False): {is_not_similar}")
    assert not is_not_similar, "False positive on dissimilar response"
    
    # Test variant selection
    candidates = [
        "share bank account now", # Duplicate
        "send upi id pls",        # Duplicate
        "ok tell me more about this" # Unique
    ]
    
    best = response_memory.get_dissimilar_variant(session_id, candidates, threshold=0.70)
    print(f"Best variant selected: '{best}'")
    assert best == "ok tell me more about this", "Failed to select best variant"
    
    print("Response memory tests passed")

def test_emotions():
    """Test emotion transitions."""
    print("\n--- Testing Emotion Engine ---")
    
    emotions_visited = set()
    current = EmotionState.CONFUSED
    
    print("Simulating conversation flow:")
    for i in range(20):
        # Simulate urgency in later half
        urgency = (i > 10)
        prev = current
        current = EmotionEngine.get_next_emotion(current, scammer_urgency=urgency)
        emotions_visited.add(current)
        print(f"Turn {i}: {prev.value} -> {current.value} (Urgency: {urgency})")
        
        # Test prompt generation
        prompt = EmotionEngine.get_emotion_prompt(current, "Naive User")
        assert f"EMOTION: {current.name}" in prompt
        
        # Test marker injection
        response = "ok i understand"
        marked = EmotionEngine.inject_emotion_markers(response, current)
        print(f"  Marked response: {marked}")
    
    print(f"Unique emotions visited: {len(emotions_visited)}")
    assert len(emotions_visited) >= 4, f"Only visited {len(emotions_visited)} emotions"
    print("Emotion system tests passed")

def test_context_extraction():
    """Context signals ai_agent derives from a scammer message."""
    from packages.agents.honeypot.ai_agent import extract_new_information

    info1 = extract_new_information("pay to 9876543210 immediately", [])
    assert info1["has_phone"]
    assert info1["shows_urgency"]

    info2 = extract_new_information("send to my_upi@oksbi", [])
    assert info2["has_upi"]
