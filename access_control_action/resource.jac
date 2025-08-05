import from jivas.agent.modules.system.common { node_obj }
import from jivas.agent.core.graph_node { GraphNode }

node Resource(GraphNode) {
    has name:str = "";

    def get_job_entry() {
        node_obj([<--]);
    }

    def get_name() -> str {
        return self.name;
    }

    def set_name(name:str) -> None {
        self.name = name;
    }
}
