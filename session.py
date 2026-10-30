class SessionManager:
    """
    Tracks session identifiers, enforces message order,
    and prevents duplicate messages and session replays.
    """

    def __init__(self):
        self.used_sessions = set()
        self.active_sessions = {}

    def start_session(self, session_id):
        """
        Start a new session.
        Reject previously used session identifiers.
        """

        if type(session_id) is not str:
            raise TypeError("Session ID must be a string.")

        if not session_id:
            raise ValueError("Session ID cannot be empty.")

        if session_id in self.used_sessions:
            raise ValueError("Replay attack detected.")

        self.used_sessions.add(session_id)

        self.active_sessions[session_id] = {
            "state": "started",
            "messages": set()
        }

    def register_message(self, session_id, message_type):
        """
        Enforce message order and reject duplicate messages.
        """

        if type(session_id) is not str:
            raise TypeError("Session ID must be a string.")

        if type(message_type) is not str:
            raise TypeError("Message type must be a string.")

        if session_id not in self.active_sessions:
            raise ValueError("Unknown session.")

        session = self.active_sessions[session_id]

        if session["state"] == "completed":
            raise ValueError("Session already completed.")

        expected_order = ["init", "response", "finish"]

        if message_type not in expected_order:
            raise ValueError("Unknown message type.")

        if message_type in session["messages"]:
            raise ValueError("Duplicate message detected.")

        next_index = len(session["messages"])

        if message_type != expected_order[next_index]:
            raise ValueError("Message received out of order.")

        session["messages"].add(message_type)

    def complete_session(self, session_id):
        """
        Complete a session only after all three messages.
        """

        if session_id not in self.active_sessions:
            raise ValueError("Unknown session.")

        session = self.active_sessions[session_id]

        if session["state"] == "completed":
            raise ValueError("Session already completed.")

        required_messages = {"init", "response", "finish"}

        if session["messages"] != required_messages:
            raise ValueError("Cannot complete an unfinished session.")

        session["state"] = "completed"