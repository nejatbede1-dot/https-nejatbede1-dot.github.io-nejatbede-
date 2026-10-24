PRAGMA foreign_keys = ON;

-- Enforce the five-active-session cap at the database layer as a defense-in-depth
-- guard. The Worker also trims sessions after login, but this trigger protects
-- against concurrent or non-Worker inserts that could otherwise bypass it.
CREATE TRIGGER IF NOT EXISTS trg_sessions_cap_after_insert
AFTER INSERT ON sessions
BEGIN
  DELETE FROM sessions
   WHERE user_id = NEW.user_id
     AND id NOT IN (
       SELECT id
         FROM sessions
        WHERE user_id = NEW.user_id
        ORDER BY created_at DESC, id DESC
        LIMIT 5
     );
END;
