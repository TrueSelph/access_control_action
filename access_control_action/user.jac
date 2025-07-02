import from jivas.agent.modules.agentlib.utils { Utils }
import from jivas.agent.core.graph_node { GraphNode }


node User(GraphNode) {
    has user_id:str = "";

    def get_job_entry() {
        Utils.node_obj([<--]);
    }

    def get_user_id() -> str {
        return self.user_id;
    }

    def set_user_id(user_id:str) -> None {
        self.user_id = user_id;
    }
}
