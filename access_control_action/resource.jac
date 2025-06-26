import:py from jivas.agent.modules.agentlib.utils { Utils }
import:jac from jivas.agent.core.graph_node { GraphNode }

node Resource :GraphNode: {
    has name:str = "";

    can get_job_entry() {
        Utils.node_obj([<--]);
    }

    can get_name() -> str {
        return self.name;
    }

    can set_name(name:str) -> None {
        self.name = name;
    }
}
