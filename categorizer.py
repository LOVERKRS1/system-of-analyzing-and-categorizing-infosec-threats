
# Модуль категоризации событий информационной безопасности.
# Определяет категорию события на основе анализа его текстового описания.
# Поддерживает английский и русский языки.


# Словарь правил категоризации:
# ключ — категория, значение — список ключевых слов
RULES = {
    "BruteForce": [
        
        "brute force",
        "multiple login attempts",
        "many failed logins",
        "password guessing",
        "credential stuffing",
        "multiple failed logins",

        
        "подбор пароля",
        "множественные попытки входа",
        "много неудачных попыток входа",
        "многочисленные попытки входа",
        "перебор паролей",
        "атака brute force",
        "брутфорс",
        "брутфорс атака",
    ],

    "FailedLogin": [
        
        "failed login",
        "authentication failure",
        "invalid password",
        "login failed",

        
        "неудачная попытка входа",
        "ошибка аутентификации",
        "неверный пароль",
        "вход не выполнен",
        "отказ в аутентификации",
        "неуспешный вход",
    ],

    "SuccessfulLogin": [
        
        "successful login",
        "successfully logged in",
        "login succeeded",

        
        "успешный вход",
        "успешная аутентификация",
        "пользователь успешно вошел",
        "пользователь успешно вошёл",
        "вход выполнен успешно",
    ],

    "PortScan": [
        
        "port scan",
        "nmap",
        "scan detected",
        "port probe",

        
        "сканирование портов",
        "обнаружено сканирование",
        "сканирование хоста",
        "проверка портов",
        "зондирование портов",
    ],

    "DDoS": [
        
        "ddos",
        "traffic flood",
        "service unavailable",
        "syn flood",

        
        "ddos",
        "ддос",
        "ddos-атака",
        "ддос-атака",
        "атака отказа в обслуживании",
        "отказ в обслуживании",
        "поток трафика",
        "лавина трафика",
        "syn flood",
    ],

    "MalwareDetection": [
        
        "malware detected",
        "malware",
        "trojan",
        "virus",
        "ransomware",

        
        "обнаружено вредоносное по",
        "вредоносное по",
        "вредоносная программа",
        "обнаружен троян",
        "троян",
        "вирус",
        "шифровальщик",
        "ransomware",
    ],

    "PhishingAttempt": [
        
        "phishing",
        "phishing email",
        "phishing message",
        "fake login page",

        
        "фишинг",
        "фишинговое письмо",
        "фишинговое сообщение",
        "поддельная страница входа",
        "поддельная форма входа",
        "письмо с фишинговой ссылкой",
    ],
}

# Категория по умолчанию
DEFAULT_CATEGORY = "SecurityEvent"

#Нормализация текста
def normalize_text(text: str) -> str:
    return text.lower().replace("ё", "е").strip()

# Определяет категорию события по описанию.
# param description: текст события
# return: категория события
def categorize_event(description: str) -> str:
    text = normalize_text(description)
    # Перебор всех категорий и ключевых слов
    for category, keywords in RULES.items():
        for keyword in keywords:
            if normalize_text(keyword) in text:
                return category
    # Если ничего не найдено
    return DEFAULT_CATEGORY