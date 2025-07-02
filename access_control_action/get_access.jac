import logging;
import from logging { Logger }
import from jivas.agent.core.agent { Agent }
import from jivas.agent.action.action { Action }
import from jivas.agent.action.actions { Actions }
import from jivas.agent.action.interact_action { InteractAction }
import from jivas.agent.action.interact_graph_walker { interact_graph_walker }


walker get_access(interact_graph_walker) {

    has response:dict = {};
    has channel:str = "default";
    has resource:str = "any";

    # set up logger
    static has logger:Logger = logging.getLogger(__name__);

    can on_agent with Agent entry {
        visit [-->](`?Actions);
    }

    can on_actions with Actions entry {
        visit [-->](`?Action)(?enabled==True)(?label=='AccessControlAction');
    }

    can on_action with Action entry {
        self.response = here.get_access(channel=self.channel, resource=self.resource);
    }
}