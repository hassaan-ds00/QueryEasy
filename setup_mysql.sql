-- Run once as a MySQL admin. Replace your_database and every password.
-- Three accounts = three safety levels. QueryEasy uses the weakest one that works.

-- 1) READER: SELECT / SHOW / DESCRIBE / EXPLAIN
CREATE USER 'queryeasy_ro'@'localhost' IDENTIFIED BY 'CHANGE_ME_1'
  WITH MAX_QUERIES_PER_HOUR 1000 MAX_USER_CONNECTIONS 5;
GRANT SELECT ON your_database.* TO 'queryeasy_ro'@'localhost';

-- 2) WRITER: INSERT / UPDATE / DELETE (no structure changes)
CREATE USER 'queryeasy_rw'@'localhost' IDENTIFIED BY 'CHANGE_ME_2'
  WITH MAX_USER_CONNECTIONS 5;
GRANT SELECT, INSERT, UPDATE, DELETE ON your_database.* TO 'queryeasy_rw'@'localhost';

-- 3) ADMIN: CREATE / ALTER / DROP / TRUNCATE / RENAME / INDEX
CREATE USER 'queryeasy_admin'@'localhost' IDENTIFIED BY 'CHANGE_ME_3'
  WITH MAX_USER_CONNECTIONS 3;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES, CREATE VIEW
  ON your_database.* TO 'queryeasy_admin'@'localhost';

-- Optional: let admins create NEW databases (limit them to a name pattern for safety)
-- GRANT ALL PRIVILEGES ON `qe\_%`.* TO 'queryeasy_admin'@'localhost';
-- GRANT SELECT ON `qe\_%`.* TO 'queryeasy_ro'@'localhost';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON `qe\_%`.* TO 'queryeasy_rw'@'localhost';

FLUSH PRIVILEGES;

-- Never grant: GRANT OPTION, FILE, SUPER, PROCESS, or ALL on *.*
-- Check: SHOW GRANTS FOR 'queryeasy_admin'@'localhost';
