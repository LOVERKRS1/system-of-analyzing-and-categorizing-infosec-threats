# Модуль построения онтологии событий информационной безопасности.

# Создает RDF-граф, включающий:
# - классы
# - иерархию
# - свойства
# - экземпляры событий

from rdflib import Graph, Namespace, RDF, RDFS, Literal

from categorizer import categorize_event

# Пространство имен онтологии
EX = Namespace("http://example.org/infosec#")

# Базовые классы
CLASSES = [
    "SecurityEvent",
    "NetworkEvent",
    "AuthenticationEvent",
    "MalwareEvent",
    "Incident",
    "Asset",
    "Host",
    "User",
    "Severity",
    "Source",
]

# Иерархия классов
SUBCLASS_RELATIONS = {
    "NetworkEvent": "SecurityEvent",
    "AuthenticationEvent": "SecurityEvent",
    "MalwareEvent": "SecurityEvent",
    "PortScan": "NetworkEvent",
    "DDoS": "NetworkEvent",
    "FailedLogin": "AuthenticationEvent",
    "SuccessfulLogin": "AuthenticationEvent",
    "BruteForce": "AuthenticationEvent",
    "MalwareDetection": "MalwareEvent",
    "PhishingAttempt": "MalwareEvent",
}


DATA_PROPERTIES = ["hasDescription", "hasSourceIP"]

# Свойства
OBJECT_PROPERTIES = [
    "hasSeverity",
    "belongsToCategory",
    "initiatedBy",
    "affectsHost",
    "relatedToUser",
    "mayLeadTo",
]

# Нормализация
def normalize_to_uri(value: str) -> str:
    return (
        value.replace(" ", "_")
        .replace("-", "_")
        .replace(".", "_")
        .replace(":", "_")
        .replace("/", "_")
    )

# Добавляет классы и свойства в онтологию
def add_base_schema(graph: Graph) -> None:
    
    for class_name in CLASSES:
        graph.add((EX[class_name], RDF.type, RDFS.Class))

    for child, parent in SUBCLASS_RELATIONS.items():
        graph.add((EX[child], RDF.type, RDFS.Class))
        graph.add((EX[child], RDFS.subClassOf, EX[parent]))

    for prop in DATA_PROPERTIES + OBJECT_PROPERTIES:
        graph.add((EX[prop], RDF.type, RDF.Property))

# Строит RDF-граф онтологии.
# param events: список событий
# return: RDF-граф
def add_severity_instances(graph: Graph) -> None:
    # Добавляем уровни критичности
    for severity in ["Low", "Medium", "High"]:
        graph.add((EX[severity], RDF.type, EX.Severity))

# Добавляем события
def add_event_instance(graph: Graph, event_id: str, event: dict) -> None:
    description = event["description"]
    source_ip = event["source_ip"]
    target_host = event["target_host"]
    severity = event.get("severity", "Medium")
    user = event.get("user")
    incident = event.get("incident")

    category = categorize_event(description)
    # Атрибуты
    graph.add((EX[event_id], RDF.type, EX[category]))
    graph.add((EX[event_id], EX.hasDescription, Literal(description)))
    graph.add((EX[event_id], EX.hasSourceIP, Literal(source_ip)))
    graph.add((EX[event_id], EX.hasSeverity, EX[severity]))
    graph.add((EX[event_id], EX.belongsToCategory, EX[category]))

    source_id = f"Source_{normalize_to_uri(source_ip)}"
    graph.add((EX[source_id], RDF.type, EX.Source))
    graph.add((EX[event_id], EX.initiatedBy, EX[source_id]))

    host_id = normalize_to_uri(target_host)
    graph.add((EX[host_id], RDF.type, EX.Host))
    graph.add((EX[event_id], EX.affectsHost, EX[host_id]))

    if user:
        user_id = normalize_to_uri(user)
        graph.add((EX[user_id], RDF.type, EX.User))
        graph.add((EX[event_id], EX.relatedToUser, EX[user_id]))

    if incident:
        incident_id = normalize_to_uri(incident)
        graph.add((EX[incident_id], RDF.type, EX.Incident))
        graph.add((EX[event_id], EX.mayLeadTo, EX[incident_id]))

# Строим онтологию
def build_ontology(events: list[dict]) -> Graph:
    graph = Graph()
    graph.bind("ex", EX)
    add_base_schema(graph)
    add_severity_instances(graph)
    for index, event in enumerate(events, start=1):
        add_event_instance(graph, f"Event{index:03d}", event)
    return graph

# Сохраняет онтологию в файл.
def save_ontology(events: list[dict], output_path: str = "infosec_ontology.rdf") -> str:
    graph = build_ontology(events)
    graph.serialize(destination=output_path, format="xml")
    return output_path
