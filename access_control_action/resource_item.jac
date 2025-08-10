import from jivas.agent.modules.system.common { node_obj }
import from jivas.agent.core.graph_node { GraphNode }

node ResourceItem(GraphNode) {
    has name:str = "";

    def get_job_entry() {
        return node_obj([<--]);
    }

    def get_name() -> str {
        return self.name;
    }

    def set_name(name:str) -> None {
        self.name = name;
    }
}
