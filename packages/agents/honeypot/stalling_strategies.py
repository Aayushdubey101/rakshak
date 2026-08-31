import random

STALLING_TACTICS = {
    "TECHNICAL_DIFFICULTY": [
        "I'm trying to open the link but it says 'Server Error'. Should I try again?",
        "My internet is acting up... the page isn't loading. One moment.",
        "It says 'Payment Pending' on my screen but didn't go through. What do I do?",
        "The app crashed when I clicked send. Did you get it?",
        "I need to update my UPI app, it's asking for a mandatory update."
    ],
    "VERIFICATION_REQUESTS": [
        "Wait, my son said I should check the name first. What is the name on your account?",
        "Can you send me a screenshot of where I need to click? I'm confused.",
        "My bank is asking for the beneficiary name to confirm. What should I put?",
        "Is this a business account or personal? I need to select the right option.",
        "Can you verify your phone number? I want to make sure I'm sending it to the right person."
    ],
    "FAMILY_CONSULTATION": [
        "Hold on, let me ask my son, he usually helps me with this.",
        "My wife is saying verify the number first. Two seconds.",
        "I'm on a call with my nephew, he's asking for the reference number.",
        "Wait, my daughter just walked in. Let me show her this.",
        "I need to find my glasses, can't read the OTP."
    ],
    "CONFUSION_DELAY": [
        "I don't see the 'Pay' button. Is it the green one or the blue one?",
        "There are so many options here... 'Quick Transfer', 'IMPS', 'NEFT'. Which one?",
        "It's asking for a VPA. What is that?",
        "I typed the amount but nothing happened. Do I press enter?",
        "Sorry, I think I clicked the wrong thing. Let me start over."
    ],
    "PROCESS_QUESTIONS": [
        "How long will it take for you to receive it?",
        "Will I get a confirmation message immediately?",
        "Is there a transaction fee? It's showing 5 rupees extra.",
        "Do I need to add remarks? What should I write?",
        "Can I send half now and half later when I get the receipt?"
    ]
}

class StallingEngine:
    @staticmethod
    def get_stalling_message(tactic_category: str = None) -> str:
        """
        Returns a stalling message. If category is None, picks a random one.
        """
        if not tactic_category or tactic_category not in STALLING_TACTICS:
            # Pick a random category
            tactic_category = random.choice(list(STALLING_TACTICS.keys()))
            
        return random.choice(STALLING_TACTICS[tactic_category])

    @staticmethod
    def select_tactic(turn_count: int, gap_since_intel: int) -> str:
        """
        Selects an appropriate tactic based on conversation state.
        """
        if gap_since_intel > 3:
            # If we haven't got intel in a while, maybe pretend we are trying but failing (Technical)
            return "TECHNICAL_DIFFICULTY"
            
        # Rotate tactics based on turns to avoid repetition (simple hash)
        categories = list(STALLING_TACTICS.keys())
        return categories[turn_count % len(categories)]
