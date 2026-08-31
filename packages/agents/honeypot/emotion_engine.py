import random
from enum import Enum
from typing import Dict

class EmotionState(Enum):
    """Possible emotional states for the honeypot agent."""
    CONFUSED = "confused"           # "what? i dont understand"
    CURIOUS = "curious"             # "tell me more how does this work"
    EXCITED = "excited"             # "wow really?? amazing!"
    CAUTIOUS = "cautious"           # "hmm not sure... is this safe?"
    TRUSTING = "trusting"           # "ok i believe you lets do it"
    FRUSTRATED = "frustrated"       # "ugh this is not working"
    SCARED = "scared"               # "oh no what if something goes wrong"
    EAGER = "eager"                 # "yes yes im ready lets go"
    SKEPTICAL = "skeptical"         # "wait how do i know this is real"

class EmotionEngine:
    """
    Manages emotional progression throughout a conversation.
    Ensures varied, realistic emotional responses.
    """
    
    # Emotion transition probabilities (from_state -> to_state -> probability)
    TRANSITIONS = {
        EmotionState.CONFUSED: {
            EmotionState.CURIOUS: 0.6,
            EmotionState.CAUTIOUS: 0.3,
            EmotionState.FRUSTRATED: 0.1
        },
        EmotionState.CURIOUS: {
            EmotionState.EXCITED: 0.5,
            EmotionState.CAUTIOUS: 0.3,
            EmotionState.TRUSTING: 0.2
        },
        EmotionState.EXCITED: {
            EmotionState.EAGER: 0.4,
            EmotionState.SKEPTICAL: 0.3,
            EmotionState.TRUSTING: 0.3
        },
        EmotionState.CAUTIOUS: {
            EmotionState.SKEPTICAL: 0.4,
            EmotionState.TRUSTING: 0.3,
            EmotionState.CONFUSED: 0.3
        },
        EmotionState.TRUSTING: {
            EmotionState.EAGER: 0.5,
            EmotionState.FRUSTRATED: 0.3,
            EmotionState.CAUTIOUS: 0.2
        },
        EmotionState.FRUSTRATED: {
            EmotionState.SCARED: 0.4,
            EmotionState.CONFUSED: 0.3,
            EmotionState.EAGER: 0.3  # Desperate to fix
        },
        EmotionState.SCARED: {
            EmotionState.CAUTIOUS: 0.5,
            EmotionState.CONFUSED: 0.3,
            EmotionState.TRUSTING: 0.2  # Seeking help
        },
        EmotionState.EAGER: {
            EmotionState.FRUSTRATED: 0.4,  # Technical issues
            EmotionState.EXCITED: 0.3,
            EmotionState.TRUSTING: 0.3
        },
        EmotionState.SKEPTICAL: {
            EmotionState.CAUTIOUS: 0.4,
            EmotionState.CURIOUS: 0.3,
            EmotionState.TRUSTING: 0.3  # Convinced
        }
    }
    
    # Linguistic markers for each emotion
    MARKERS = {
        EmotionState.CONFUSED: [
            "wait what", "i dont get it", "huh?", "confused", "what u mean", 
            "can u explain", "not understanding"
        ],
        EmotionState.CURIOUS: [
            "interesting", "tell me more", "how does it work", "really?", 
            "what happens next", "explain pls"
        ],
        EmotionState.EXCITED: [
            "wow!", "amazing", "great!!", "awesome", "cant wait", 
            "this is cool", "omg yes"
        ],
        EmotionState.CAUTIOUS: [
            "hmm", "not sure", "is this safe", "should i", "what if", 
            "little worried", "need to think"
        ],
        EmotionState.TRUSTING: [
            "ok i believe u", "sounds good", "lets do it", "you seem legit", 
            "alright then", "im ready"
        ],
        EmotionState.FRUSTRATED: [
            "ugh", "not working", "this is hard", "why isnt it", 
            "getting error", "so complicated", "annoying"
        ],
        EmotionState.SCARED: [
            "oh no", "what if something goes wrong", "scared", "nervous", 
            "hope its ok", "worried now"
        ],
        EmotionState.EAGER: [
            "yes yes", "hurry", "lets go", "im ready", "do it now", 
            "quickly", "want to start"
        ],
        EmotionState.SKEPTICAL: [
            "wait", "how do i know", "prove it", "sounds too good", 
            "suspicious", "not convinced", "show me"
        ]
    }
    
    @staticmethod
    def get_next_emotion(
        current: EmotionState, 
        scammer_urgency: bool = False
    ) -> EmotionState:
        """
        Determines the next emotional state based on conversation flow.
        
        Args:
            current: Current emotion state
            scammer_urgency: Whether scammer is showing urgency/pressure
        
        Returns:
            Next emotion state
        """
        if current not in EmotionEngine.TRANSITIONS:
            return EmotionState.CONFUSED
        
        transitions = EmotionEngine.TRANSITIONS[current]
        
        # If scammer shows urgency, bias towards SCARED or FRUSTRATED
        if scammer_urgency:
            if random.random() < 0.4:
                return EmotionState.SCARED if random.random() < 0.5 else EmotionState.FRUSTRATED
        
        # Weighted random selection
        states = list(transitions.keys())
        weights = list(transitions.values())
        
        return random.choices(states, weights=weights)[0]
    
    @staticmethod
    def get_emotion_prompt(emotion: EmotionState, persona: str) -> str:
        """
        Returns an instruction prompt for the AI to adopt the specified emotion.
        
        Args:
            emotion: Target emotional state
            persona: Current persona name
        
        Returns:
            Prompt instruction for the AI
        """
        prompts = {
            EmotionState.CONFUSED: f"""
EMOTION: CONFUSED
- Sound uncertain and lost
- Ask basic questions for clarification  
- Use phrases like: "wait what", "i dont get it", "what u mean"
- Show you're trying to understand but struggling
""",
            EmotionState.CURIOUS: f"""
EMOTION: CURIOUS
- Show genuine interest in learning more
- Ask follow-up questions
- Use phrases like: "interesting", "tell me more", "how does it work"
- Seem engaged but not committed yet
""",
            EmotionState.EXCITED: f"""
EMOTION: EXCITED
- Show enthusiasm and eagerness
- Use exclamation marks naturally
- Use phrases like: "wow!", "amazing", "this is great"
- Sound hopeful and positive
""",
            EmotionState.CAUTIOUS: f"""
EMOTION: CAUTIOUS
- Express hesitation and concern
- Ask about safety and risks
- Use phrases like: "hmm", "not sure", "is this safe"
- Sound protective of yourself
""",
            EmotionState.TRUSTING: f"""
EMOTION: TRUSTING
- Show you believe them
- Express willingness to proceed
- Use phrases like: "ok i believe u", "lets do it", "sounds good"
- Lower your guard
""",
            EmotionState.FRUSTRATED: f"""
EMOTION: FRUSTRATED
- Express annoyance with technical difficulties
- Mention things not working
- Use phrases like: "ugh", "not working", "why isnt it"
- Sound like you want it to work but can't make it happen
""",
            EmotionState.SCARED: f"""
EMOTION: SCARED
- Express worry and anxiety
- Mention potential negative outcomes
- Use phrases like: "oh no", "what if", "worried"
- Seek reassurance
""",
            EmotionState.EAGER: f"""
EMOTION: EAGER
- Show impatience to proceed
- Express readiness to act
- Use phrases like: "yes yes", "lets go", "im ready"
- Sound like you want to move forward quickly
""",
            EmotionState.SKEPTICAL: f"""
EMOTION: SKEPTICAL
- Express doubt and need for proof
- Question claims
- Use phrases like: "wait", "how do i know", "prove it"
- Sound unconvinced but still engaged
"""
        }
        
        return prompts.get(emotion, prompts[EmotionState.CONFUSED])
    
    @staticmethod
    def inject_emotion_markers(response: str, emotion: EmotionState) -> str:
        """
        Adds subtle emotional markers to a response if they're missing.
        
        Args:
            response: Original AI response
            emotion: Target emotion
        
        Returns:
            Response with added emotional markers (if needed)
        """
        markers = EmotionEngine.MARKERS.get(emotion, [])
        
        # Check if response already has emotional markers
        has_markers = any(marker.lower() in response.lower() for marker in markers)
        
        if not has_markers and markers:
            # Add a subtle marker at the start or end
            marker = random.choice(markers)
            
            if random.random() < 0.5:
                # Prepend
                response = f"{marker}... {response}"
            else:
                # Append
                response = f"{response} {marker}"
        
        return response

# Session-based emotion tracking
emotion_tracker: Dict[str, EmotionState] = {}

def get_session_emotion(session_id: str) -> EmotionState:
    """Get current emotion for a session, defaults to CONFUSED."""
    return emotion_tracker.get(session_id, EmotionState.CONFUSED)

def update_session_emotion(
    session_id: str, 
    scammer_urgency: bool = False
) -> EmotionState:
    """Update emotion for a session and return new state."""
    current = get_session_emotion(session_id)
    next_emotion = EmotionEngine.get_next_emotion(current, scammer_urgency)
    emotion_tracker[session_id] = next_emotion
    return next_emotion
