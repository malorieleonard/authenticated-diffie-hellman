import unittest

from session import SessionManager


class TestSessionManager(unittest.TestCase):

    def test_start_session(self):
        manager = SessionManager()
        manager.start_session("session123")

        self.assertIn(
            "session123",
            manager.active_sessions
        )

    def test_replay_session(self):
        manager = SessionManager()
        manager.start_session("session123")

        with self.assertRaises(ValueError):
            manager.start_session("session123")

    def test_register_message(self):
        manager = SessionManager()
        manager.start_session("session123")
        manager.register_message("session123", "init")

        self.assertIn(
            "init",
            manager.active_sessions["session123"]["messages"]
        )

    def test_duplicate_message(self):
        manager = SessionManager()
        manager.start_session("session123")
        manager.register_message("session123", "init")

        with self.assertRaises(ValueError):
            manager.register_message("session123", "init")

    def test_unknown_session(self):
        manager = SessionManager()

        with self.assertRaises(ValueError):
            manager.register_message("unknown", "init")

    def test_complete_session(self):
        manager = SessionManager()
        manager.start_session("session123")

        manager.register_message("session123", "init")
        manager.register_message("session123", "response")
        manager.register_message("session123", "finish")

        manager.complete_session("session123")

        self.assertEqual(
            manager.active_sessions["session123"]["state"],
            "completed"
        )

    def test_invalid_session_id(self):
        manager = SessionManager()

        with self.assertRaises(TypeError):
            manager.start_session(123)

    def test_response_before_init(self):
        manager = SessionManager()
        manager.start_session("session123")

        with self.assertRaises(ValueError):
            manager.register_message("session123", "response")

    def test_finish_before_response(self):
        manager = SessionManager()
        manager.start_session("session123")
        manager.register_message("session123", "init")

        with self.assertRaises(ValueError):
            manager.register_message("session123", "finish")

    def test_incomplete_session_cannot_finish(self):
        manager = SessionManager()
        manager.start_session("session123")
        manager.register_message("session123", "init")

        with self.assertRaises(ValueError):
            manager.complete_session("session123")

    def test_completed_session_rejects_messages(self):
        manager = SessionManager()
        manager.start_session("session123")

        manager.register_message("session123", "init")
        manager.register_message("session123", "response")
        manager.register_message("session123", "finish")
        manager.complete_session("session123")

        with self.assertRaises(ValueError):
            manager.register_message("session123", "init")


if __name__ == "__main__":
    unittest.main()