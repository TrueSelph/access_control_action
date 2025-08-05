import from jivas.agent.modules.system.common { node_obj }
import from jivas.agent.core.graph_node { GraphNode }
import from actions.jivas.access_control_action.user { User }



node Group(GraphNode) {
    has name:str = "";

    def get_group_entry() {
        node_obj([<--]);
    }

    def get_name() -> str {
        return self.name;
    }

    def set_name(name:str) -> None {
        self.name = name;
    }

    def has_user(user_id:str="all") -> bool {
        return (self spawn _has_user(user_id=user_id)).user;
    }
}



walker _has_user {
    has user_id:str = "";
    has user:bool = False;

    obj __specs__ {
        # make this a private walker
        static has private: bool = True;
    }

    can on_group with Group entry {
        if(here.name in ["all", "any"]) {
            self.user = True;
        }else {
            visit [-->](`?User)(?user_id==self.user_id);
        }
    }

    can on_user with User entry {
        self.user = True;
    }
}