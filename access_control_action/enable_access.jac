import logging;
import from logging { Logger }
import from jivas.agent.core.agent { Agent }
import from jivas.agent.action.action { Action }
import from jivas.agent.action.actions { Actions }
import from jivas.agent.action.interact_action { InteractAction }
import from jivas.agent.modules.action.path { action_walker_path }
import from jivas.agent.action.agent_graph_walker { agent_graph_walker }


walker enable_access(agent_graph_walker) {

    has response:dict = {};
    has user:str = "";
    has group:str = "";
    has channel:str = "";
    has resource:str = "";
    has enabled:bool = False;
    has reporting:bool = True;

    # set up logger
    static has logger:Logger = logging.getLogger(__name__);

    class __specs__ {
        static has private: bool = False;
        static has path: str = action_walker_path(__module__);
    }

    can on_agent with Agent entry {
        visit [-->](`?Actions);
    }

    can on_actions with Actions entry {
        visit [-->](`?Action)(?enabled==True)(?label=='AccessControlAction');
    }

    can on_action with Action entry {
        self.response = here.enable_access(user=self.user, group=self.group, channel=self.channel, resource=self.resource, enabled=self.enabled);
        if self.reporting {
            report self.response;
        }
    }
}