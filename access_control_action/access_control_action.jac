import:py re;
import:py traceback;
import:jac from jivas.agent.core.agent { Agent }
import:jac from jivas.agent.action.action { Action }
import:jac from jivas.agent.action.actions { Actions }
import:jac from jivas.agent.memory.collection { Collection }
import:jac from jivas.agent.action.interact_action { InteractAction }

import:jac from actions.jivas.access_control_action.channel { Channel }
import:jac from actions.jivas.access_control_action.channels { Channels }
import:jac from actions.jivas.access_control_action.any_channel { AnyChannel }
import:jac from actions.jivas.access_control_action.default_channel { DefaultChannel }
import:jac from actions.jivas.access_control_action.resource { Resource }
import:jac from actions.jivas.access_control_action.resources { Resources }
import:jac from actions.jivas.access_control_action.any_resource { AnyResource }
import:jac from actions.jivas.access_control_action.group { Group }
import:jac from actions.jivas.access_control_action.groups { Groups }
import:jac from actions.jivas.access_control_action.any_group { AnyGroup }
import:jac from actions.jivas.access_control_action.user { User }
import:jac from actions.jivas.access_control_action.users { Users }
import:jac from actions.jivas.access_control_action.any_user { AnyUser }

import:jac from actions.jivas.access_control_action.allow { Allow }
import:jac from actions.jivas.access_control_action.deny { Deny }


node AccessControlAction :Action: {
    # allows access control permissions to be defined per channel, action and session_id; maintains perm configs as a record of session_ids and associated role

    has exceptions:list = []; # collection of actions which are exempt from permissions

    has permissions:dict = {
        "default": { # channel
            "any":{ # resource, e.g. action type; 'any' is default
                "deny":["test"], # can accommodate specific session ids, session group name or 'all'
                "allow":["all", "5926431530"] # can accommodate specific session ids, session group name or 'all'
            },
            "all":{ # resource, e.g. action type; 'any' is default
                "deny":["99999"], # can accommodate specific session ids, session group name or 'all'
                "allow":["1111", "666666", "test"] # can accommodate specific session ids, session group name or 'all'
            }
        },
        "whatsapp": {
            "any":{
                "deny":[],
                "allow":["all", "5926431530", "test"]
            },
            "TypesenseRetrievalInteractAction": {
                "allow":["5926431535", "test"],
                "deny":["5926431537"]
            }
        },
        "any": {
            "any":{
                "deny":[],
                "allow":["all", "any"]
            }
        }

    };

    has purge_collection:bool = False;

    has session_groups:dict = {
        "test": [
            "5926431530",
            "5926431531",
            "5926431532"
        ]
    }; # contains group name as key and list of session_ids as the value

    can on_register() {
        self.import_permissions(self.permissions, self.session_groups, self.purge_collection);
    }

    can add_session_group(group_name:str, session_ids:list) {
        # adds a session group to the session_groups dict

        for session_id in session_ids {
            result = self.add_user_to_group(group_name, session_id);
            if not result {
                return False;
            }
        }
        return True;
    }

    can add_exception(action_label:str) {
        # adds an action to the exceptions list if it's not already present
        if action_label not in self.exceptions {
            self.exceptions.append(action_label);
        }
    }

    can in_session_group(session_id:str, group_names:list) {
        # checks if a session_id is in any of the session groups provided in the list
        groups = self.get_groups(include_users=True);
        for name in group_names {
            for group in groups {
                if(session_id in group['users'] and group['name'] == name) {
                    return True;
                }
            }
        }

        return False;
    }

    can healthcheck() -> bool {
        try {
            # Check if 'permissions' is a dict and has at least one key
            if (type(self.permissions) == dict && len(self.permissions.keys()) > 0) {
                # Define allowed and required keys
                allowed_channels = ["default", "whatsapp", "facebook"];
                required_channels = ["deny", "allow"];

                # Iterate over each channel in the 'permissions'
                for channel in self.permissions.keys() {
                    if (channel in allowed_channels) {
                        if ("any" in self.permissions[channel]) {
                            # Iterate over each access type in the channel permissions
                            for access in self.permissions[channel] {
                                # Get the resource value for this access
                                resource_value = self.permissions[channel][access];

                                if (type(resource_value) == dict) {
                                    # Check each required access exists
                                    for required_channel in required_channels {
                                        if (required_channel not in resource_value) {
                                            return False;  # Missing required access
                                        }
                                    }
                                }
                                else {
                                    return False;  # Resource value is not a dict
                                }
                            }
                        }
                        else {
                            return False;  # 'any' key missing in channel
                        }
                    }
                    else {
                        return False;  # Channel not in allowed_channels
                    }
                }
                return True;  # All checks passed
            }
            return False;  # 'permissions' is not a dict or is empty
        } except Exception as e {
            self.logger.error(f"An exception occurred in {self.label}:\n{traceback.format_exc()}\n");
            return False;
        }
    }

    can import_permissions(permissions:dict={}, session_groups:dict={}, purge_collection:bool=False) -> bool {
        # pruge collection before migration
        if(purge_collection){
            self.get_agent().get_memory().purge_collection_memory(self.label);
        }

        # get collection
        collection = self.get_collection();

        last_channel = "";
        last_resource = "";
        permission_resource_allow = [];
        permission_resource_deny = [];

        # add permission to collection
        for permission_channel in permissions {
            # add channel to collection
            channel = (collection spawn _add_channel(permission_channel)).channel;
            # self.logger.warning(f"channel: {channel}, permission_channel: {permission_channel}");

            for permission_resource in permissions[permission_channel] {
                if last_channel != permission_channel {
                    # add new resource to channel
                    resource = (collection spawn _add_resource(name=permission_resource, new_resource=True)).resource;
                    channel ++> resource;
                }
                # get allow and deny permissions
                permission_resource_allow = list(set(permissions[permission_channel][permission_resource]["allow"]));
                permission_resource_deny = list(set(permissions[permission_channel][permission_resource]["deny"]));

                # add allow permissions
                for item in permission_resource_allow {
                    if ( bool(re.match(r'^[a-zA-Z_]+$', item)) or item == "any" ) {
                        if last_resource != permission_resource {
                            # add group to collection
                            group = (collection spawn _add_group(name=item, new_group=True)).group;
                            resource +:Allow:+> group;
                        }
                    }else {
                        if last_resource != permission_resource {
                            # add user to collection
                            user = (collection spawn _add_user(user_id=item, new_user=True)).user;
                            resource +:Allow:+> user;
                        }
                    }
                }

                # add deny permissions
                for item in permission_resource_deny {
                    # check if item in both allow and deny
                    if(item not in permission_resource_allow) {
                        if ( bool(re.match(r'^[a-zA-Z_]+$', item)) or item == "any" ) {
                            if last_resource != permission_resource {
                                # add group to collection
                                group = (collection spawn _add_group(name=item, new_group=True)).group;
                                resource +:Deny:+> group;
                            }
                        }else {
                            if last_resource != permission_resource {
                                # add user to collection
                                user = (collection spawn _add_user(user_id=item, new_user=True)).user;
                                resource +:Deny:+> user;
                            }
                        }
                    } else {
                        self.logger.error(f"{item} is in both allow and deny");
                        return False;
                    }
                }

                last_resource = permission_resource;
            }

            last_channel = permission_channel;
            last_resource = "";
        }

        # add user to group
        for session_group in session_groups {
            group = (collection spawn _add_group(session_group)).group;

            for user in session_groups[session_group] {
                # check if user is in both allow and deny
                if(user in permission_resource_allow and user in permission_resource_deny) {
                    self.logger.error(f"{user} is in both allow and deny");
                    return False;
                }else{
                    # add user to collection group
                    user = (collection spawn _add_user(user)).user;
                    group ++> user;
                }
            }
        }
        return True;
    }

    can export_permissions() -> dict {
        collection = self.get_collection();
        ss = self.in_session_group("5926431531", ["supervisors"]);
        self.logger.warning(f"5926431531: {ss}");
        return (collection spawn _export_permissions());
    }

    can has_action_access(session_id:str, action_label:str="all", channel:str="default") -> bool {
        if(self.enabled){
            collection = self.get_collection();
            if not channel {
                channel = "default";
            }

            if not action_label {
                action_label = "all";
            }

            if not session_id {
                session_id = "any";
            }
            
            return (collection spawn _has_access(user_id=session_id, channel=channel, resource=action_label)).access;
        } else {
            return True;
        }
    }


    # add permissions to collection
    can add_channel(name:str) -> dict {
        collection = self.get_collection();
        return (collection spawn _add_channel(name=name));
    }

    can add_resource(name:str, parent_node:str = "") -> dict {
        collection = self.get_collection();
        return (collection spawn _add_resource(name=name, parent_node=parent_node));
    }

    can add_group(name:str, parent_node:str = "") -> dict {
        collection = self.get_collection();
        return (collection spawn _add_group(name=name, parent_node=parent_node));
    }

    can add_user(user_id:str, parent_node:str = "") -> dict {
        collection = self.get_collection();
        return (collection spawn _add_user(user_id=user_id, parent_node=parent_node));
    }

    can add_permission(channel:str, resource:str, allow:bool, user_id:str) -> bool {
        try {
            collection = self.get_collection();

            channel_result = (collection spawn _add_channel(name=channel));
            # add edge to new node
            if channel_result.new_channel {
                collection ++> channel_result.channel;
            }

            resource_result = (collection spawn _add_resource(name=resource, parent_node=channel_result.channel.id));
            # add edge to new node
            if resource_result.new_resource {
                channel_result.channel ++> resource_result.resource;
            }


            if allow {
                if ( bool(re.match(r'^[a-zA-Z_]+$', user_id)) or user_id == "any" ) {
                    group_result = (collection spawn _add_group(name=user_id, parent_node=resource_result.resource.id));
                    # delete existing edges and add new edge
                    resource_result.resource del -:Allow:-> group_result.group;
                    resource_result.resource del -:Deny:-> group_result.group;
                    resource_result.resource +:Allow:+> group_result.group;
                }else {
                    user_result = (collection spawn _add_user(user_id=user_id, parent_node=resource_result.resource.id));
                    # delete existing edges and add new edge
                    resource_result.resource del -:Deny:-> user_result.user;
                    resource_result.resource del -:Allow:-> user_result.user;
                    resource_result.resource +:Allow:+> user_result.user;
                }
            } else {
                if ( bool(re.match(r'^[a-zA-Z_]+$', user_id)) or user_id == "any" ) {
                    group_result = (collection spawn _add_group(name=user_id, parent_node=resource_result.resource.id));
                    # delete existing edges and add new edge
                    resource_result.resource del -:Allow:-> group_result.group;
                    resource_result.resource del -:Deny:-> group_result.group;
                    resource_result.resource +:Deny:+> group_result.group;
                }else {
                    user_result = (collection spawn _add_user(user_id=user_id, parent_node=resource_result.resource.id));
                    # delete existing edges and add new edge
                    resource_result.resource del -:Allow:-> user_result.user;
                    resource_result.resource del -:Deny:-> user_result.user;
                    resource_result.resource +:Deny:+> user_result.user;
                }
            }
            return True;
        } except Exception as e {
            self.logger.error(f"Error adding permission: {e}");
            return False;
        }
    }

    can add_user_to_group(group:str, user_id:str) -> bool {
        collection = self.get_collection();

        try {
            group_result = (collection spawn _add_group(name=group));
            user_result = (collection spawn _add_user(user_id=user_id, parent_node=group_result.group.id));
            # add edge to new node
            if user_result.new_user {
                group_result.group ++> user_result.user;
            }
            return True;
        } except Exception as e {
            self.logger.error(f"Error adding user to group: {e}");
            return False;
        }
    }


    # delete permissions from collection
    can delete_channel(name:str="") -> bool {
        collection = self.get_collection();
        result = (collection spawn _delete_channel(name=name)).deleted;
        if result {
            return True;
        }
        return False;
    }

    can delete_resource(channel:str, resource:str="") -> bool {
        collection = self.get_collection();
        result = (collection spawn _delete_resource(channel=channel, resource=resource)).deleted;
        if result {
            return True;
        }
        return False;
    }

    can delete_group(name:str="") -> bool {
        collection = self.get_collection();
        result = (collection spawn _delete_group(name=name)).deleted;
        if result {
            return True;
        }
        return False;
    }

    can delete_user(user_id:str="", group:str="") -> bool {
        collection = self.get_collection();
        return (collection spawn _delete_user(user_id=user_id, group=group)).deleted;
    }

    can get_interact_actions -> list[str] {
        return (self.get_agent() spawn _get_interact_actions()).actions;
    }

    # get permissions
    can get_channels() -> list[str] {
        collection = self.get_collection();
        return (collection spawn _get_channels()).channels;
    }

    can get_resources() -> list[str] {
        collection = self.get_collection();
        return (collection spawn _get_resources()).resources;
    }

    can get_groups(include_users:bool=False) -> list {
        collection = self.get_collection();
        return (collection spawn _get_groups(include_users=include_users)).groups;
    }

    can get_users(out_of_groups:bool=False) -> list[str] {
        collection = self.get_collection();
        return (collection spawn _get_users(out_of_groups=out_of_groups)).users;
    }

    can get_access(channel:str="Default", resource:str="any") -> dict {
        collection = self.get_collection();
        return (collection spawn _get_access(channel=channel, resource=resource)).access;
    }

    can enable_access(user:str, channel:str, resource:str, enabled:bool=True) -> bool {
        collection = self.get_collection();
        return (collection spawn _enable_access(user=user, channel=channel, resource=resource, enabled=enabled)).result;
    }

}

# add permissions to collection

walker _add_channel {
    has name:str = "";
    has channel:Channel = None;
    has new_channel:bool = False;

    can on_collection with Collection entry {
        visit [-->](`?Channels) else {
            channels = Channels();
            here ++> channels;
            visit [-->](`?Channels);
        }
    }

    can on_channels with Channels entry {
        visit [-->](`?Channel)(?name == self.name) else {
            if self.name == "any" {
                channel = AnyChannel(name=self.name);
            }elif(self.name == "default") {
                channel = DefaultChannel(name=self.name);
            } else {
                channel = Channel(name=self.name);
            }
            here ++> channel;
            self.channel = channel;
            self.new_channel = True;

        }
    }

    can on_channel with Channel entry {
        self.channel = here;
    }
}

walker _add_resource {
    has name:str = "";
    has resource:Resource = None;
    has parent_node:str = "";
    has new_resource:bool = False;

    can on_collection with Collection entry {
        visit [-->](`?Resources) else {
            resources = Resources();
            here ++> resources;
            visit [-->](`?Resources);
        }
    }

    can on_resources with Resources entry {
        if self.new_resource {
            if self.name == "any" {
                resource = AnyResource(name=self.name);
            }else{
                resource = Resource(name=self.name);
            }
            here ++> resource;
            self.resource = resource;
        }else {
            visit [-->](`?Resource)(?name==self.name) else {
                if self.name == "any" {
                    resource = AnyResource(name=self.name);
                }else{
                    resource = Resource(name=self.name);
                }
                here ++> resource;
                self.resource = resource;
                self.new_resource = True;
            }
        }
    }

    can on_resource with Resource entry {
        edges = [<--];
        edge_found = False;
        for e in edges {
            if e.id == self.parent_node {
                edge_found = True;
                break;
            }
        }
        if not edge_found {
            self.new_resource = True;
        }
        self.resource = here;
    }
}

walker _add_group {
    has name:str = "";
    has group:Group = None;
    has parent_node:str = "";
    has new_group:bool = False;

    can on_collection with Collection entry {
        visit [-->](`?Groups) else {
            groups = Groups();
            here ++> groups;
            visit [-->](`?Groups);
        }
    }

    can on_groups with Groups entry {
        visit [-->](`?Group)(?name == self.name) else {
            if self.name in ["any", "all"] {
                group = AnyGroup(name=self.name);
            } else {
                group = Group(name=self.name);
            }
            here ++> group;
            self.group = group;
            self.new_group = True;
        }
    }

    can on_group with Group entry {
        edges = [<--];
        edge_found = False;
        for e in edges {
            if e.id == self.parent_node {
                edge_found = True;
                break;
            }
        }
        if not edge_found {
            self.new_group = True;
        }
        self.group = here;
    }
}

walker _add_user {
    has user_id:str = "";
    has user:User = None;
    has parent_node:str = "";
    has new_user:bool = False;

    can on_collection with Collection entry {
        visit [-->](`?Users) else {
            users = Users();
            here ++> users;
            visit [-->](`?Users);
        }
    }

    can on_users with Users entry {
        visit [-->](`?User)(?user_id == self.user_id) else {
            if self.user_id in ["any", "all"] {
                user = AnyUser(user_id=self.user_id);
            } else {
                user = User(user_id=self.user_id);
            }
            here ++> user;
            self.user = user;
            self.new_user = True;
        }
    }

    can on_user with User entry {
        edges = [<--];
        edge_found = False;
        for e in edges {
            if e.id == self.parent_node {
                edge_found = True;
                break;
            }
        }
        if not edge_found {
            self.new_user = True;
        }
        self.user = here;
    }
}

# delete permissions from collection
walker _delete_channel {
    has name:str = "";
    has deleted:list = [];

    can on_collection with Collection entry {
        visit [-->](`?Channels);
    }

    can on_channels with Channels entry {
        if self.name {
            visit [-->](`?Channel)(?name == self.name);
        } else {
            visit [-->](`?Channel);
        }
    }

    can on_channel with Channel entry {
        self.deleted.append(here);
        visit [-->](`?Resource);
    }

    can on_resource with Resource entry {
        self.deleted.append(here);
        edges = [<--];
        if(len(edges) <= 2) {
            self.deleted.append(here);
        }
        visit [-->];
    }

    can on_group with Group entry {
        edges = [<--];
        if(len(edges) <= 2) {
            self.deleted.append(here);
        }
        visit [-->];
    }

    can on_user with User entry {
        edges = [<--];
        if(len(edges) <= 2) {
            self.deleted.append(here);
        }
    }

    can on_exit with exit {
        for item in self.deleted {
            Jac.destroy(item);
        }
    }
}

walker _delete_resource {
    has channel:str = "";
    has resource:str = "";
    has deleted:list = [];

    can on_collection with Collection entry {
        if self.channel {
            visit [-->](`?Channels);
        }else {
            visit [-->](`?Resources);
        }
    }

    can on_channels with Channels entry {
        if self.channel {
            visit [-->](`?Channel)(?name == self.channel);
        } else {
            visit [-->](`?Channel);
        }
    }

    can on_channel with Channel entry {
        if self.resource {
            visit [-->](`?Resource)(?name == self.resource);
        } else {
            visit [-->](`?Resource);
        }
    }

    can on_resources with Resources entry {
        if self.resource {
            visit [-->](`?Resource)(?name == self.resource);
        } else {
            visit [-->](`?Resource);
        }
    }

    can on_resource with Resource entry {
        self.deleted.append(here);
        visit [-->];
    }

    can on_group with Group entry {
        edges = [<--];
        if(len(edges) <= 2) {
            self.deleted.append(here);
        }
        visit [-->];
    }

    can on_user with User entry {
        edges = [<--];
        if(len(edges) <= 2) {
            self.deleted.append(here);
        }
    }

    can on_exit with exit {
        for item in self.deleted {
            Jac.destroy(item);
        }
    }
}

walker _delete_group {
    has name:str = "";
    has deleted:list = [];

    can on_collection with Collection entry {
        visit [-->](`?Groups);
    }

    can on_groups with Groups entry {
        visit [-->](`?Group)(?name == self.name);
    }

    can on_group with Group entry {
        self.deleted.append(here);
        visit [-->](`?User);
    }

    can on_user with User entry {
        edges = [<--];
        if(len(edges) <= 2) {
            self.deleted.append(here);
        }
    }

    can on_exit with exit {
        for item in self.deleted {
            Jac.destroy(item);
        }
    }
}

walker _delete_user {
    has user_id:str = "";
    has deleted:bool = False;
    has parent_nodes:list = [];
    has group:str = "";
    has collection:Collection = None;
    has edge_deleted:bool = False;

    can on_collection with Collection entry {
        self.collection = here;
        if self.group and not self.edge_deleted {
            visit [-->](`?Groups);
        }else{
            visit [-->](`?Users);
        }
    }

    can on_groups with Groups entry {
        visit [-->](`?Group)(?name == self.group);
    }

    can on_group with Group entry {
        self.edge_deleted = True;
        here del --> [-->](`?User)(?user_id == self.user_id);
        self.deleted = True;
        visit self.collection;
    }

    can on_users with Users entry {
        visit [-->](`?User)(?user_id == self.user_id);
    }

    can on_user with User entry {
        parent_nodes = [<--];
        if self.group {
            if(len(parent_nodes) <= 1) {
                self.deleted = True;
                Jac.destroy(here);
            }
        }else{
            self.deleted = True;
            Jac.destroy(here);
        }

    }
}

# get get_permissions
walker _get_channels {
    has channels:list = [];

    can on_collection with Collection entry {
        visit [-->](`?Channels);
    }

    can on_channels with Channels entry {
        visit [-->](`?Channel);
    }

    can on_channel with Channel entry {
        self.channels.append(here);
    }
}

walker _get_resources {
    has resources:list = [];

    can on_collection with Collection entry {
        visit [-->](`?Resources);
    }

    can on_resources with Resources entry {
        visit [-->](`?Resource);
    }

    can on_resource with Resource entry {
        self.resources.append(here);
    }
}

walker _get_groups {
    has groups:list = [];
    has include_users:bool = False;

    can on_collection with Collection entry {
        visit [-->](`?Groups);
    }

    can on_groups with Groups entry {
        visit [-->](`?Group);
    }

    can on_group with Group entry {
        users = [-->](`?User);
        user_ids = [];
        for user in users {
            user_ids.append(user.user_id);
        }

        if(self.include_users){
            self.groups.append({"name": here.name, "users": user_ids});
        }else {
            self.groups.append(here);
        }
    }
}

walker _get_users {
    has users:list = [];
    has out_of_groups:bool = False;

    can on_collection with Collection entry {
        visit [-->](`?Users);
    }

    can on_users with Users entry {
        visit [-->](`?User);
    }

    can on_user with User entry {
        if self.out_of_groups {
            groups = [<--](`?Group);
            if len(groups) == 0 {
                self.users.append(here);
            }
        }else{
            self.users.append(here);
        }
    }
}

walker _get_access {
    has channel:str = "default";
    has resource:str = "any";
    has access:dict = {};

    obj __specs__ {
        static has private:bool = True;
    }

    can on_collection with Collection entry {
        visit [-->];
    }

    can on_channels with Channels entry {
        visit [-->](`?Channel)(?name==self.channel);
    }

    can on_channel with Channel entry {
        visit [-->](`?Resource)(?name==self.resource);
    }

    can on_resource with Resource entry {
        allow_access = [];
        deny_access = [];

        allow = [-:Allow:->](`?User);
        deny = [-:Deny:->](`?User);

        allow_access.extend(allow);
        deny_access.extend(deny);

        # check allow group access for each group
        allow_group = [-:Allow:->](`?Group);
        allow_access.extend(allow_group);

        deny_group = [-:Deny:->](`?Group);
        deny_access.extend(deny_group);

        self.access = {
            "allow": allow_access,
            "deny": deny_access
        };
    }
}


# import permssion to access control
walker _export_permissions {
    has permissions:dict = {};
    has session_groups:dict = {};

    can on_collection with Collection entry {
        visit [-->];
    }

    can on_channels with Channels entry {
        visit [-->](`?Channel);
    }

    can on_channel with Channel entry {
        visit [-->](`?Resource);
    }

    can on_resource with Resource entry {
        channel = [<--](`?Channel)[0].name;
        allow_list = [];
        deny_list = [];

        allow_nodes = [-:Allow:->];
        deny_nodes = [-:Deny:->];

        for allow_node in allow_nodes {
            if allow_node.get_type() in ["Group", "AnyGroup"] {
                allow_list.append(allow_node.name);
            }else{
                allow_list.append(allow_node.user_id);
            }
        }

        for deny_node in deny_nodes {
            if deny_node.get_type() in ["Group", "AnyGroup"] {
                deny_list.append(deny_node.name);
            }else{
                deny_list.append(deny_node.user_id);
            }
        }

        if channel not in self.permissions.keys() {
            self.permissions[channel] = {here.name: {"allow": allow_list, "deny": deny_list}};
        }elif(here.name not in self.permissions[channel].keys()) {
            self.permissions[channel][here.name] = {"allow": allow_list, "deny": deny_list};
        } else{
            self.permissions[channel][here.name]["allow"].extend(allow_list);
            self.permissions[channel][here.name]["deny"].extend(deny_list);
        }

        visit [-->](`?Group);

    }

    can on_group with Group entry {
        user_id = [];
        user_nodes = [-->](`?User);
        for user_node in user_nodes {
            if(here.name not in self.session_groups.keys()) {
                self.session_groups[here.name] = [user_node.user_id];
            }elif(user_node.user_id not in self.session_groups[here.name]) {
                self.session_groups[here.name].append(user_node.user_id);
            }
        }

    }
}

# check access
walker _has_access {
    has channel:str = "default";
    has resource:str = "any";
    has user_id:str = "all";
    has access:bool = False;

    obj __specs__ {
        static has private:bool = True;
    }

    can on_collection with Collection entry {
        visit [-->];
    }

    can on_channels with Channels entry {
        visit [-->](`?Channel)(?name==self.channel);
    }

    can on_channel with Channel entry {
        resources = [<--](`?Resource);
        visit [-->](`?Resource)(?name==self.resource) else {
            visit [-->](`?Resource)(?name=="any");
        }
    }

    can on_resource with Resource entry {
        if not self.user_id {
            self.user_id = "all";
        }
        # allow = [->:Allow:(?enabled==True):->](`?User)(?user_id==self.user_id);
        # deny = [->:Deny:(?enabled==True):->](`?User)(?user_id==self.user_id);
        allow = [-:Allow:->](`?User)(?user_id==self.user_id);
        deny = [-:Deny:->](`?User)(?user_id==self.user_id);

        # set access to false if deny
        if deny {
            self.access = False;
        }


        # set access to true if allow
        if allow {
            self.access = True;
        }


        # check for deny group access for each group
        deny_group = [-:Deny:->](`?Group);
        for group in deny_group {
            deny_group_access = group.has_user(user_id=self.user_id);
            if deny_group_access {
                self.access = False;
                break;
            }
        }


        # check allow group access for each group
        allow_group = [-:Allow:->](`?Group);
        for group in allow_group {
            allow_group_access = group.has_user(user_id=self.user_id);
            if allow_group_access {
                self.access = True;
                break;
            }
        }

    }
}

# get interact actions
walker _get_interact_actions {

    has actions:list[str] = ["all", "any"];

    obj __specs__ {
        static has private:bool = True;
    }

    can on_agent with Agent entry {
        visit [-->](`?Actions);
    }

    can on_actions with Actions entry {
        visit [-->];
    }

    can on_interact_action with InteractAction entry {
        if(here.get_type() not in ["ExitInteractAction"]){
            self.actions.append(here.get_type());
        }
    }

}


walker _enable_access {

    has enabled:bool = True;
    has user:str = "";
    has channel:str = "";
    has resource:str = "";
    has result:bool = False;

    obj __specs__ {
        static has private:bool = True;
    }

    can on_collection with Collection entry {
        print("collection");
        visit [-->](`?Channels);
    }
    can on_channels with Channels entry {
        print("channels");
        visit [-->](`?Channel)(?name==self.channel);
    }
    can on_channel with Channel entry {
        print("channel");
        visit [-->](`?Resource)(?name==self.resource);
    }
    can on_resource with Resource entry {
        print("resource");
        allow_user_edges = [-:Allow:->](`?User)(?user_id==self.user);
        deny_user_edges = [-:Deny:->](`?User)(?user_id==self.user);
        allow_group_edges = [-:Allow:->](`?Group)(?name==self.user);
        deny_group_edges = [-:Deny:->](`?Group)(?name==self.user);


        if allow_user_edges {
            print(allow_user_edges[0]);
            here del --> [-->](`?User)(?user_id == allow_user_edges[0].user_id);
            here +:Allow(enabled=self.enabled):+> allow_user_edges[0];
                # inception +>:Similar(similarity_score=0.85):+> interstellar;
        }

        if deny_user_edges {
            print(deny_user_edges[0]);
            here del --> [-->](`?User)(?user_id == deny_user_edges[0].user_id);
            here +:Deny:+> deny_user_edges[0];
            # here +Deny(enabled=self.enabled)+> deny_user_edges[0];
        }

        # if allow_group_edges {
        #     print(allow_group_edges[0]);
        #     here del --> [-->](`?Group)(?name == allow_group_edges[0].name);
        #     here +Allow(enabled=self.enabled)+> allow_group_edges[0];
        # }

        # if deny_group_edges {
        #     print(deny_group_edges[0]);
        #     here del --> [-->](`?Group)(?name == deny_group_edges[0].name);
        #     here +Deny(enabled=self.enabled)+> deny_group_edges[0];
        # }

        self.result = True;
    }
}


# _enable_access

