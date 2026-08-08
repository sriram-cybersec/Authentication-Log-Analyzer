from datetime import datetime, timedelta


def calculate_severity(attempt_count):
    """Return alert severity based on the number of failed attempts."""
    if attempt_count >= 20:
        return "CRITICAL"
    elif attempt_count >= 10:
        return "HIGH"
    return "MEDIUM"


def determine_attack_type(unique_users):
    """Classify suspicious authentication activity."""
    if len(unique_users) == 1:
        return "Possible Brute-Force Attack"
    return "Possible Multi-Account Attack"


def parse_log_line(line):
    """Validate and parse a single authentication log entry."""
    line = line.strip()

    if not line:
        return None

    parts = line.split()

    if len(parts) != 5:
        print("WARNING: Malformed log entry skipped:", line)
        return None

    if (
        not parts[3].startswith("user=")
        or not parts[4].startswith("ip=")
    ):
        print("WARNING: Invalid user/IP format skipped:", line)
        return None

    date = parts[0]
    time = parts[1]
    event = parts[2]

    user = parts[3].split("=", 1)[1]
    ip = parts[4].split("=", 1)[1]

    if not user or not ip:
        print("WARNING: Empty user/IP skipped:", line)
        return None

    try:
        timestamp = datetime.strptime(
            f"{date} {time}",
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        print("WARNING: Invalid timestamp skipped:", line)
        return None

    return timestamp, event, user, ip


def find_correlated_success(
    ip,
    successful_logins,
    last_time,
    unique_users,
    success_window
):
    """Find a successful login correlated with suspicious failures."""
    if ip not in successful_logins:
        return None

    successful_logins[ip].sort(key=lambda x: x[0])

    for success_time, success_user in successful_logins[ip]:

        time_after_attack = success_time - last_time

        if (
            success_time > last_time
            and time_after_attack <= success_window
            and success_user in unique_users
        ):
            return (
                success_time,
                success_user,
                time_after_attack
            )

    return None


def analyze_logs(log_file_path="auth.log"):
    """
    Read authentication logs and detect suspicious activity.

    Returns a list of generated alert dictionaries.
    """

    failed_attempts = {}
    successful_logins = {}

    with open(log_file_path, "r") as log_file:

        for line in log_file:

            parsed_log = parse_log_line(line)

            if parsed_log is None:
                continue

            timestamp, event, user, ip = parsed_log

            if event == "LOGIN_FAILED":

                if ip not in failed_attempts:
                    failed_attempts[ip] = []

                failed_attempts[ip].append(
                    (timestamp, user)
                )

            elif event == "LOGIN_SUCCESS":

                if ip not in successful_logins:
                    successful_logins[ip] = []

                successful_logins[ip].append(
                    (timestamp, user)
                )

    threshold = 5
    time_window = timedelta(minutes=10)
    success_window = timedelta(minutes=15)

    alerts = []

    for ip, timestamps in failed_attempts.items():

        timestamps.sort(key=lambda x: x[0])

        for i in range(len(timestamps)):

            window_attempts = []

            first_attempt = timestamps[i][0]

            for j in range(i, len(timestamps)):

                current_attempt = timestamps[j][0]

                if (
                    current_attempt - first_attempt
                    <= time_window
                ):
                    window_attempts.append(
                        timestamps[j]
                    )
                else:
                    break

            if len(window_attempts) < threshold:
                continue

            users = [
                attempt[1]
                for attempt in window_attempts
            ]

            unique_users = set(users)

            actual_attempts = len(window_attempts)

            attack_type = determine_attack_type(
                unique_users
            )

            severity = calculate_severity(
                actual_attempts
            )

            first_time = window_attempts[0][0]
            last_time = window_attempts[-1][0]

            time_difference = (
                last_time - first_time
            )

            alert = {
                "type": attack_type,
                "severity": severity,
                "ip": ip,
                "targeted_users": users,
                "unique_users": unique_users,
                "attempts": actual_attempts,
                "time_difference": time_difference
            }

            alerts.append(alert)

            correlated_success = find_correlated_success(
                ip,
                successful_logins,
                last_time,
                unique_users,
                success_window
            )

            if correlated_success is not None:

                (
                    success_time,
                    success_user,
                    time_after_attack
                ) = correlated_success

                alert["compromise_indicator"] = True
                alert["successful_user"] = success_user
                alert["successful_login_time"] = success_time
                alert["time_after_attack"] = (
                    time_after_attack
                )

            else:

                alert["compromise_indicator"] = False

            # Prevent duplicate alerts from overlapping windows
            break

    return alerts


def print_alerts(alerts):
    """Display generated security alerts."""

    for alert in alerts:

        print(
            "\nALERT:",
            alert["type"]
        )

        print(
            "Severity:",
            alert["severity"]
        )

        print(
            "IP Address:",
            alert["ip"]
        )

        print(
            "Targeted Users:",
            alert["targeted_users"]
        )

        print(
            "Unique Users:",
            alert["unique_users"]
        )

        print(
            "Number of Unique Users:",
            len(alert["unique_users"])
        )

        print(
            "Failed Attempts:",
            alert["attempts"]
        )

        print(
            "Time Difference:",
            alert["time_difference"]
        )

        if alert["compromise_indicator"]:

            print(
                "\nCRITICAL ALERT: "
                "Successful Login After "
                "Suspicious Failures!"
            )

            print(
                "IP Address:",
                alert["ip"]
            )

            print(
                "User:",
                alert["successful_user"]
            )

            print(
                "Previous Failed Attempts:",
                alert["attempts"]
            )

            print(
                "Successful Login Time:",
                alert["successful_login_time"]
            )

            print(
                "Time After Attack:",
                alert["time_after_attack"]
            )

            print(
                "Possible Account "
                "Compromise Indicator"
            )


def main():
    """Run Authentication Log Analyzer."""

    alerts = analyze_logs("auth.log")

    print_alerts(alerts)


if __name__ == "__main__":
    main()