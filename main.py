# Главный файл запуска системы.

from pathlib import Path

from categorizer import categorize_event
from graph_builder import build_event_graph, save_event_reports, visualize_graph
from ontology import save_ontology


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "report"

# Возвращает тестовые события.
def get_demo_events() -> list[dict]:
    return [
        {
            "description": "Multiple login attempts detected from external IP 192.168.1.100",
            "source_ip": "192.168.1.100",
            "target_host": "auth-01",
            "severity": "High",
            "user": "admin",
            "incident": "AccountCompromise",
        },
        {
            "description": "Authentication failure for admin account on auth-01",
            "source_ip": "10.0.0.15",
            "target_host": "auth-01",
            "severity": "Medium",
            "user": "admin",
            "incident": "UnauthorizedAccessAttempt",
        },
        {
            "description": "Successful login for backup operator on backup-01",
            "source_ip": "10.0.0.25",
            "target_host": "backup-01",
            "severity": "Low",
            "user": "backup_operator",
            "incident": "PrivilegeUse",
        },
        {
            "description": "Port scan detected on host web-01 using nmap",
            "source_ip": "172.16.0.50",
            "target_host": "web-01",
            "severity": "Medium",
            "incident": "Reconnaissance",
        },
        {
            "description": "DDoS traffic flood detected against portal-01",
            "source_ip": "203.0.113.10",
            "target_host": "portal-01",
            "severity": "High",
            "incident": "ServiceDisruption",
        },
        {
            "description": "Malware detected on workstation pc-22 after suspicious file execution",
            "source_ip": "10.10.10.20",
            "target_host": "pc-22",
            "severity": "High",
            "user": "employee_02",
            "incident": "MalwareInfection",
        },
        {
            "description": "Phishing email detected with fake login page for employee_01",
            "source_ip": "198.51.100.77",
            "target_host": "mail-01",
            "severity": "Medium",
            "user": "employee_01",
            "incident": "CredentialTheftAttempt",
        },
        {
            "description": "Brute force attack detected against admin account from IP 185.23.45.10",
            "source_ip": "185.23.45.10",
            "target_host": "auth-02",
            "severity": "High",
            "user": "admin",
            "incident": "AccountCompromise",
        },
        {
            "description": "Invalid password entered for user root on server db-01",
            "source_ip": "10.0.0.33",
            "target_host": "db-01",
            "severity": "Medium",
            "user": "root",
            "incident": "UnauthorizedAccessAttempt",
        },
        {
            "description": "User john successfully logged in to vpn-gateway",
            "source_ip": "10.0.1.12",
            "target_host": "vpn-01",
            "severity": "Low",
            "user": "john",
            "incident": "NormalAccess",
        },
        {
            "description": "Nmap scan detected from IP 45.67.89.10 targeting internal network",
            "source_ip": "45.67.89.10",
            "target_host": "fw-01",
            "severity": "Medium",
            "incident": "Reconnaissance",
        },
        {
            "description": "SYN flood detected causing service unavailable on web server",
            "source_ip": "198.18.0.1",
            "target_host": "web-02",
            "severity": "High",
            "incident": "ServiceDisruption",
        },
        {
            "description": "Trojan detected on workstation pc-45 during antivirus scan",
            "source_ip": "10.10.20.30",
            "target_host": "pc-45",
            "severity": "High",
            "user": "employee_03",
            "incident": "MalwareInfection",
        },
        {
            "description": "Ransomware activity detected encrypting files on server file-01",
            "source_ip": "10.10.30.40",
            "target_host": "file-01",
            "severity": "High",
            "incident": "CriticalMalwareInfection",
        },
        {
            "description": "Phishing message detected pretending to be bank notification",
            "source_ip": "203.0.113.55",
            "target_host": "mail-02",
            "severity": "Medium",
            "user": "employee_04",
            "incident": "CredentialTheftAttempt",
        },
        {
            "description": "Fake login page detected in email campaign targeting employees",
            "source_ip": "192.0.2.77",
            "target_host": "mail-03",
            "severity": "Medium",
            "incident": "PhishingCampaign",
        },
        {
            "description": "Multiple failed logins detected on ssh service of server linux-01",
            "source_ip": "172.20.10.5",
            "target_host": "linux-01",
            "severity": "High",
            "incident": "BruteForceAttempt",
        },
        {
            "description": "Множественные попытки входа в учетную запись admin с IP 192.168.1.100",
            "source_ip": "192.168.1.100",
            "target_host": "auth-01",
            "severity": "High",
            "user": "admin",
            "incident": "AccountCompromise",
        },
        {
            "description": "Обнаружено сканирование портов на хосте web-01",
            "source_ip": "172.16.0.50",
            "target_host": "web-01",
            "severity": "Medium",
            "incident": "Reconnaissance",
        },
        {
            "description": "Обнаружено вредоносное ПО на рабочей станции pc-22",
            "source_ip": "10.10.10.20",
            "target_host": "pc-22",
            "severity": "High",
            "user": "employee_02",
            "incident": "MalwareInfection",
        },
        {
            "description": "Фишинговое письмо обнаружено в почтовом ящике пользователя employee_01",
            "source_ip": "198.51.100.77",
            "target_host": "mail-01",
            "severity": "Medium",
            "user": "employee_01",
            "incident": "CredentialTheftAttempt",
        }
    ]

# Основная функция программы.
def main() -> None:
    events = get_demo_events()

    print("Категорирование событий:")
    for idx, event in enumerate(events, start=1):
        category = categorize_event(event["description"])
        print(f"{idx}. {event['description']} -> {category}")
        
    # Сохранение онтологии
    rdf_path = save_ontology(events, str(BASE_DIR / "infosec_ontology.rdf"))

    # Построение графа
    graph = build_event_graph(events)
    image_path = visualize_graph(graph, str(BASE_DIR / "infosec_graph.png"))
    report_files = save_event_reports(events, str(REPORT_DIR))

    print(f"\nОнтология сохранена: {rdf_path}")
    print(f"Общий граф сохранен: {image_path}")
    print("Файлы примеров в папке report:")
    for path in report_files:
        print(f"- {path}")


if __name__ == "__main__":
    main()
