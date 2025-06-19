import:py logging;
import:py from logging { Logger }
import:jac from jivas.agent.core.agent { Agent }
import:jac from jivas.agent.action.action { Action }
import:jac from jivas.agent.action.actions { Actions }
import:jac from jivas.agent.action.interact_graph_walker { interact_graph_walker }


walker delete_permission :interact_graph_walker: {

    has item:str = "";
    has value:str = "";
    has channel:str = "";
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
        if(item == "user") {
            self.response = here.delete_user(user_id=self.value);
        }elif(item == "group") {
            self.response = here.delete_group(name=self.value);
        }elif(item == "channel") {
            self.response = here.delete_channel(name=self.value);
        }elif(item == "resource") {
            self.response = here.delete_resource(channel=self.channel, resource=self.value);
        }
    }

}