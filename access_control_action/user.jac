import:py from jivas.agent.modules.agentlib.utils { Utils }
import:jac from jivas.agent.core.graph_node { GraphNode }


node User :GraphNode: {
    has user_id:str = "";

    can get_job_entry() {
        Utils.node_obj([<--]);
    }

    can get_user_id() -> str {
        return self.user_id;
    }

    can set_user_id(user_id:str) -> None {
        self.user_id = user_id;
    }
}
