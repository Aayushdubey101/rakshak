from enum import Enum
from typing import Dict, Any

class ConversationState(Enum):
    INITIAL_CONTACT = "initial"
    BUILDING_TRUST = "trust"
    SHOWING_INTEREST = "interest"
    FAKE_COMPLIANCE = "compliance"
    INTELLIGENCE_EXTRACTION = "extraction"
    DELAY_TACTICS = "delay"
    GRACEFUL_EXIT = "exit"

class StateManager:
    @staticmethod
    def get_state(turn_count: int, intel_score: int) -> ConversationState:
        """
        Determines the current conversation state based on turns and intelligence gathered.
        """
        # Early stages
        if turn_count <= 2:
            return ConversationState.INITIAL_CONTACT
        
        if turn_count <= 4:
            return ConversationState.BUILDING_TRUST
            
        if turn_count <= 7:
            return ConversationState.SHOWING_INTEREST
            
        # Mid stages - getting deeper
        if turn_count <= 10:
            return ConversationState.FAKE_COMPLIANCE
            
        # Main extraction phase
        if turn_count <= 15:
            return ConversationState.INTELLIGENCE_EXTRACTION
            
        # Late stages - stalling if needed or exiting
        # If we have good intel (score > 50), start winding down or keep stalling for more?
        # The goal is 20+ turns.
        if turn_count <= 20:
             return ConversationState.DELAY_TACTICS
             
        return ConversationState.GRACEFUL_EXIT

    @staticmethod
    def get_behavior_guidance(state: ConversationState) -> Dict[str, str]:
        """
        Returns behavioral guidance for the AI agent based on the current state.
        """
        guidance = {
            ConversationState.INITIAL_CONTACT: {
                "tone": "Confused, hesitant, but slightly curious.",
                "goal": "Establish contact, act naive, ask basic clarification questions.",
                "avoid": "Agreeing immediately, giving personal info."
            },
            ConversationState.BUILDING_TRUST: {
                "tone": "Cautiously interested, asking for reassurance.",
                "goal": "Build rapport, make the scammer feel they are hooking you.",
                "avoid": "Being too eager, technical jargon."
            },
            ConversationState.SHOWING_INTEREST: {
                "tone": "Excited but still needing guidance.",
                "goal": "Show willingness to proceed, ask 'how-to' questions.",
                "avoid": "Committing money yet."
            },
            ConversationState.FAKE_COMPLIANCE: {
                "tone": "Trying to follow instructions but failing technically.",
                "goal": "Pretend to start the process, encounter minor issues.",
                "avoid": "Success, actually sending money."
            },
            ConversationState.INTELLIGENCE_EXTRACTION: {
                "tone": "Helpful but stuck, asking for alternative methods.",
                "goal": "Subtly ask for UPI, phone, or bank details to 'fix' the issue.",
                "avoid": "Direct interrogation."
            },
            ConversationState.DELAY_TACTICS: {
                "tone": "Frustrated with technology, apologetic.",
                "goal": "Stall for time, make up excuses, ask to wait.",
                "avoid": "Ending the conversation."
            },
            ConversationState.GRACEFUL_EXIT: {
                "tone": "Resigned, giving up, or drifting away.",
                "goal": "End the conversation naturally or stop responding effectively.",
                "avoid": "New questions."
            }
        }
        return guidance.get(state, guidance[ConversationState.INITIAL_CONTACT])
