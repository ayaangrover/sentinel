# Sentinel CLI

A Python-based Command Line Interface (CLI) for teachers to use the Sentinel extension and server.

### Commands

- **list-students**

  List active student sessions.

  ```sh
  python main.py list-students
  ```

- **view-history**

  View browsing history for a student.

  ```sh
  python main.py view-history <studentId>
  ```

- **add-rule**

  Add an allowed site rule.

  ```sh
  python main.py add-rule <siteUrl>
  ```

- **delete-rule**

  Delete an allowed site rule by its rule ID.

  ```sh
  python main.py delete-rule <ruleId>
  ```

- **clear-entries**

  Clear all active student entries.

  ```sh
  python main.py clear-entries
  ```
