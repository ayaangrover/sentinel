import argparse
import requests
import sys

SERVER_URL = "https://sentinel.ayaangrover.hackclub.app"

def list_students():
    try:
        res = requests.get(f"{SERVER_URL}/students")
        res.raise_for_status()
        students = res.json()
        if not students:
            print("No active students.")
        else:
            for s in students:
                status = "Online" if s.get("online") else "Offline"
                print(f"Student ID: {s['userId']}\n  Current Tab: {s.get('currentTab', 'N/A')}\n  Last Activity: {s.get('lastActivity')}\n  Status: {status}\n")
    except Exception as err:
        print("Error listing students:", err)

def view_history(student_id):
    try:
        res = requests.get(f"{SERVER_URL}/history", params={"userId": student_id})
        res.raise_for_status()
        history = res.json()
        if not history:
            print(f"No history found for student {student_id}")
        else:
            print(f"Browsing history for student {student_id}:")
            for entry in history:
                print(f"  Tab: {entry.get('tabVisited')}, Timestamp: {entry.get('timestamp')}")
    except Exception as err:
        print("Error fetching history:", err)

def add_rule(site_url):
    try:
        res = requests.get(f"{SERVER_URL}/rules")
        res.raise_for_status()
        rules = res.json()
    except Exception as err:
        print("Error fetching rules:", err)
        return

    new_rule = {
        "id": max([rule.get("id", 0) for rule in rules], default=0) + 1,
        "condition": { "url": site_url },
        "action": { "type": "whitelist" }
    }
    rules.append(new_rule)
    try:
        res = requests.post(f"{SERVER_URL}/rules", json={"rules": rules})
        res.raise_for_status()
        print("Rule added:", new_rule)
    except Exception as err:
        print("Error updating rules:", err)

def delete_rule(rule_id):
    try:
        res = requests.get(f"{SERVER_URL}/rules")
        res.raise_for_status()
        rules = res.json()
    except Exception as err:
        print("Error fetching rules:", err)
        return

    updated_rules = [rule for rule in rules if rule.get("id") != rule_id]
    try:
        res = requests.post(f"{SERVER_URL}/rules", json={"rules": updated_rules})
        res.raise_for_status()
        print(f"Rule {rule_id} deleted (if existed).")
    except Exception as err:
        print("Error updating rules:", err)

def clear_entries():
    try:
        res = requests.delete(f"{SERVER_URL}/clear-entries")
        res.raise_for_status()
        print("All entries cleared.")
    except Exception as err:
        print("Error clearing entries:", err)

def main():
    parser = argparse.ArgumentParser(description="Sentinel Teacher CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-students", help="List active student sessions.")

    history_parser = subparsers.add_parser("view-history", help="View browsing history for a student.")
    history_parser.add_argument("studentId", help="Student's ID")

    add_rule_parser = subparsers.add_parser("add-rule", help="Add an allowed site rule.")
    add_rule_parser.add_argument("siteUrl", help="Allowed site URL (e.g., example.com)")

    delete_rule_parser = subparsers.add_parser("delete-rule", help="Delete an allowed site rule by rule ID.")
    delete_rule_parser.add_argument("ruleId", type=int, help="Rule ID to delete")

    subparsers.add_parser("clear-entries", help="Clear active student entries.")

    args = parser.parse_args()

    if args.command == "list-students":
        list_students()
    elif args.command == "view-history":
        view_history(args.studentId)
    elif args.command == "add-rule":
        add_rule(args.siteUrl)
    elif args.command == "delete-rule":
        delete_rule(args.ruleId)
    elif args.command == "clear-entries":
        clear_entries()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()