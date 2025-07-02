import logging;
import from logging { Logger }
import from jivas.agent.core.agent { Agent }
import from jivas.agent.action.action { Action }
import from jivas.agent.action.actions { Actions }
import from jivas.agent.action.interact_action { InteractAction }
import from jivas.agent.action.interact_graph_walker { interact_graph_walker }


walker get_groups(interact_graph_walker) {

    has response:dict = {};
    has group:str = "";
    has include_users:bool = False;

    # set up logger
    static has logger:Logger = logging.getLogger(__name__);

    can on_agent with Agent entry {
        visit [-->](`?Actions);
    }

    can on_actions with Actions entry {
        visit [-->](`?Action)(?enabled==True)(?label=='AccessControlAction');
    }

    can on_action with Action entry {
        self.response = here.get_groups(group=self.group, include_users=self.include_users);
    }
}