import logging;
import from logging { Logger }
import from jivas.agent.core.agent { Agent }
import from jivas.agent.action.action { Action }
import from jivas.agent.action.actions { Actions }
import from jivas.agent.action.interact_graph_walker { interact_graph_walker }


walker add_session_group(interact_graph_walker) {

    has user_id:str = "";
    has group:str = "";
    has response:bool = False;

    # set up logger
    static has logger:Logger = logging.getLogger(__name__);

    can on_agent with Agent entry {
        visit [-->](`?Actions);
    }

    can on_actions with Actions entry {
        visit [-->](`?Action)(?enabled==True)(?label=='AccessControlAction');
    }

    can on_action with Action entry {
        self.response = here.add_session_group(group_name=self.group, session_ids=[self.user_id]);
    }

}