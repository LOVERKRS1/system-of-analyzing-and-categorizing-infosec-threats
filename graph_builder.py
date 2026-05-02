#Модуль построения и визуализации графа знаний.

from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx

from categorizer import categorize_event

# Цвета на графе
NODE_COLORS = {
    "event": "#f5f5f5",
    "category": "#cfe2ff",
    "host": "#d9ead3",
    "user": "#fff2cc",
    "incident": "#f4cccc",
    "source": "#ead1dc",
}

# Создаем граф событий.
# param events: список событий
# return: граф networkx
def build_event_subgraph(event: dict, event_id: str) -> nx.DiGraph:
    graph = nx.DiGraph()

    description = event["description"]
    source_ip = event["source_ip"]
    target_host = event["target_host"]
    user = event.get("user")
    incident = event.get("incident")
    category = categorize_event(description)

    # Добавление узлов
    graph.add_node(event_id, kind="event", label=event_id, description=description)
    graph.add_node(category, kind="category", label=category)

    # Связь событие -> категория
    graph.add_edge(event_id, category, relation="belongsToCategory")

    source_node = f"Source:{source_ip}"
    graph.add_node(source_node, kind="source", label=source_ip)
    graph.add_edge(event_id, source_node, relation="initiatedBy")

    host_node = f"Host:{target_host}"
    graph.add_node(host_node, kind="host", label=target_host)
    graph.add_edge(event_id, host_node, relation="affectsHost")

    if user:
        user_node = f"User:{user}"
        graph.add_node(user_node, kind="user", label=user)
        graph.add_edge(event_id, user_node, relation="relatedToUser")

    if incident:
        incident_node = f"Incident:{incident}"
        graph.add_node(incident_node, kind="incident", label=incident)
        graph.add_edge(event_id, incident_node, relation="mayLeadTo")

    return graph


def build_event_graph(events: list[dict]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for idx, event in enumerate(events, start=1):
        subgraph = build_event_subgraph(event, f"Event{idx:03d}")
        graph = nx.compose(graph, subgraph)
    return graph

# Отрисовывает граф и сохраняет в PNG.
# param graph: граф
# param filename: имя файла
def _draw_graph(graph: nx.DiGraph, title: str, output_path: str) -> str:
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(graph, seed=42, k=1.7)

    node_colors = []
    labels = {}
    for node, attrs in graph.nodes(data=True):
        kind = attrs.get("kind", "event")
        node_colors.append(NODE_COLORS.get(kind, "#d9d9d9"))
        labels[node] = attrs.get("label", node)

    nx.draw(
        graph,
        pos,
        labels=labels,
        with_labels=True,
        node_color=node_colors,
        node_size=2600,
        font_size=9,
        arrows=True,
    )

    edge_labels = nx.get_edge_attributes(graph, "relation")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels, font_size=8)

    plt.title(title, fontsize=14)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close()
    return output_path


def visualize_graph(graph: nx.DiGraph, output_path: str = "infosec_graph.png") -> str:
    return _draw_graph(graph, "Граф знаний событий информационной безопасности", output_path)

# сохраняем картинки графа
def save_event_reports(events: list[dict], report_dir: str = "report") -> list[str]:
    report_path = Path(report_dir)
    report_path.mkdir(parents=True, exist_ok=True)

    saved_files: list[str] = []
    for idx, event in enumerate(events, start=1):
        event_id = f"Event{idx:03d}"
        subgraph = build_event_subgraph(event, event_id)
        file_path = report_path / f"png{idx}.png"
        _draw_graph(subgraph, f"Пример {idx}: {event_id}", str(file_path))
        saved_files.append(str(file_path))

    return saved_files
