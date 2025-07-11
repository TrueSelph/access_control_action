import logging;
import from logging { Logger }
import from jivas.agent.core.agent { Agent }
import from jivas.agent.action.action { Action }
import from jivas.agent.action.actions { Actions }
import from jivas.agent.action.agent_graph_walker { agent_graph_walker }


walker get_channels(agent_graph_walker) {

    has response:list[str] = [];

    # set up logger
    static has logger:Logger = logging.getLogger(__name__);

    can on_agent with Agent entry {
        self.response = here.get_channels();
    }

}