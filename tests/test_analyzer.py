from datetime import datetime, timedelta

from main import (
    calculate_severity,
    determine_attack_type,
    parse_log_line,
    find_correlated_success,
    analyze_logs,
)


def test_calculate_severity():
    assert calculate_severity(5) == "MEDIUM"
    assert calculate_severity(9) == "MEDIUM"
    assert calculate_severity(10) == "HIGH"
    assert calculate_severity(19) == "HIGH"
    assert calculate_severity(20) == "CRITICAL"


def test_determine_attack_type():
    assert determine_attack_type({"admin"}) == (
        "Possible Brute-Force Attack"
    )

    assert determine_attack_type(
        {"admin", "rahul"}
    ) == "Possible Multi-Account Attack"


def test_parse_valid_log_line():
    line = (
        "2026-08-06 10:00:00 "
        "LOGIN_FAILED user=admin ip=45.10.20.8"
    )

    result = parse_log_line(line)

    assert result is not None

    timestamp, event, user, ip = result

    assert timestamp == datetime(2026, 8, 6, 10, 0, 0)
    assert event == "LOGIN_FAILED"
    assert user == "admin"
    assert ip == "45.10.20.8"


def test_parse_invalid_timestamp():
    line = (
        "2026-99-99 10:00:00 "
        "LOGIN_FAILED user=admin ip=45.10.20.8"
    )

    assert parse_log_line(line) is None


def test_parse_malformed_log():
    line = "This is not a valid authentication log"

    assert parse_log_line(line) is None


def test_correlated_successful_login():
    ip = "45.10.20.8"

    successful_logins = {
        ip: [
            (
                datetime(2026, 8, 6, 10, 5, 0),
                "admin",
            )
        ]
    }

    last_failed_time = datetime(
        2026, 8, 6, 10, 4, 0
    )

    unique_users = {"admin"}

    success_window = timedelta(minutes=15)

    result = find_correlated_success(
        ip,
        successful_logins,
        last_failed_time,
        unique_users,
        success_window,
    )

    assert result is not None

    success_time, success_user, time_after_attack = result

    assert success_user == "admin"
    assert success_time == datetime(
        2026, 8, 6, 10, 5, 0
    )
    assert time_after_attack == timedelta(minutes=1)


def test_different_user_is_not_correlated():
    ip = "45.10.20.8"

    successful_logins = {
        ip: [
            (
                datetime(2026, 8, 6, 10, 5, 0),
                "rahul",
            )
        ]
    }

    last_failed_time = datetime(
        2026, 8, 6, 10, 4, 0
    )

    unique_users = {"admin"}

    success_window = timedelta(minutes=15)

    result = find_correlated_success(
        ip,
        successful_logins,
        last_failed_time,
        unique_users,
        success_window,
    )

    assert result is None


def test_brute_force_detection(tmp_path):
    log_file = tmp_path / "brute_force.log"

    log_file.write_text(
        "2026-08-06 10:00:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:01:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:02:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:03:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:04:00 LOGIN_FAILED user=admin ip=45.10.20.8\n",
        encoding="utf-8",
    )

    alerts = analyze_logs(str(log_file))

    assert len(alerts) == 1

    assert alerts[0]["type"] == (
        "Possible Brute-Force Attack"
    )

    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["attempts"] == 5


def test_multi_account_detection(tmp_path):
    log_file = tmp_path / "multi_account.log"

    log_file.write_text(
        "2026-08-06 10:00:00 LOGIN_FAILED user=admin ip=88.20.30.40\n"
        "2026-08-06 10:01:00 LOGIN_FAILED user=rahul ip=88.20.30.40\n"
        "2026-08-06 10:02:00 LOGIN_FAILED user=priya ip=88.20.30.40\n"
        "2026-08-06 10:03:00 LOGIN_FAILED user=sriram ip=88.20.30.40\n"
        "2026-08-06 10:04:00 LOGIN_FAILED user=test ip=88.20.30.40\n",
        encoding="utf-8",
    )

    alerts = analyze_logs(str(log_file))

    assert len(alerts) == 1

    assert alerts[0]["type"] == (
        "Possible Multi-Account Attack"
    )

    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["attempts"] == 5
    assert len(alerts[0]["unique_users"]) == 5


def test_successful_login_after_attack(tmp_path):
    log_file = tmp_path / "compromise.log"

    log_file.write_text(
        "2026-08-06 10:00:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:01:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:02:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:03:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:04:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:05:00 LOGIN_SUCCESS user=admin ip=45.10.20.8\n",
        encoding="utf-8",
    )

    alerts = analyze_logs(str(log_file))

    assert len(alerts) == 1

    assert alerts[0]["compromise_indicator"] is True
    assert alerts[0]["successful_user"] == "admin"
    assert alerts[0]["time_after_attack"] == timedelta(minutes=1)


def test_different_successful_user_not_compromised(tmp_path):
    log_file = tmp_path / "different_user.log"

    log_file.write_text(
        "2026-08-06 10:00:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:01:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:02:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:03:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:04:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:05:00 LOGIN_SUCCESS user=rahul ip=45.10.20.8\n",
        encoding="utf-8",
    )

    alerts = analyze_logs(str(log_file))

    assert len(alerts) == 1
    assert alerts[0]["compromise_indicator"] is False


def test_failures_outside_detection_window(tmp_path):
    log_file = tmp_path / "outside_window.log"

    log_file.write_text(
        "2026-08-06 10:00:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:04:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:08:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:12:00 LOGIN_FAILED user=admin ip=45.10.20.8\n"
        "2026-08-06 10:16:00 LOGIN_FAILED user=admin ip=45.10.20.8\n",
        encoding="utf-8",
    )

    alerts = analyze_logs(str(log_file))

    assert alerts == []