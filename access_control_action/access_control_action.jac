import:py re;
import:py traceback;
import:py from typing { Union }
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
        #*
        "default": { # channel
            "any":{ # resource, e.g. action type; 'any' is default
                "deny":[
                    {
                        "group": "test",
                        "enabled": True
                    }
                ], # can accommodate specific session ids, session group name or 'all'
                "allow":[
                    {
                        "group": "all",
                        "enabled": True
                    },
                    {
                        "group": "5926431530",
                        "enabled": True
                    }
                ] # can accommodate specific session ids, session group name or 'all'
            },
            "all":{ # resource, e.g. action type; 'any' is default
                "deny":[
                    {
                        "user": "99999",
                        "enabled": True
                    }
                ], # can accommodate specific session ids, session group name or 'all'
                "allow":[
                    {
                        "user": "1111",
                        "enabled": True
                    },
                    {
                        "user": "666666",
                        "enabled": True
                    },
                    {
                        "group": "test",
                        "enabled": True
                    }
                ] # can accommodate specific session ids, session group name or 'all'
            }
        },
        "whatsapp": {
            "any":{
                "deny":[],
                "allow": [
                    {
                        "group": "all",
                        "enabled": True
                    },
                    {
                        "user": "5926431530",
                        "enabled": True
                    },
                    {
                        "group": "test",
                        "enabled": True
                    }
                ]
            },
            "TypesenseRetrievalInteractAction": {
                "allow": [
                    {
                        "user": "5926431535",
                        "enabled": True
                    },
                    {
                        "group": "test",
                        "enabled": True
                    }
                ],
                "deny": [
                    {
                        "user": "5926431537",
                        "enabled": True
                    }
                ]
            }
        },
        "any": {
            "any":{
                "deny":[],
                "allow": [
                    {
                        "group": "all",
                        "enabled": True
                    },
                    {
                        "group": "any",
                        "enabled": True
                    }
                ]
            }
        }
        *#
    };
    # contains group name as key and list of session_ids as the value
    has session_groups:dict = {
        #*
        "test": [
            "5926431530",
            "5926431531",
            "5926431532"
        ]
        *#
    };

    can on_register() {
        # import permissions to collection 
        self.import_permissions(self.permissions, self.session_groups);
    }

    can convert_permissions(permissions:dict) -> dict {
        new_permissions = {};
        USER_PATTERN = r'^(\d{10,15}|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$';
        GROUP_PATTERN = r'^[a-zA-Z_][a-zA-Z0-9_]*(_[a-zA-Z0-9_]+)*$';

        for (permission_type, resources) in permissions.items() {
            new_permissions[permission_type] = {};
            for (resource, access_dict) in resources.items() {
                new_access = {
                    "allow": [],
                    "deny": []
                };
                for (access_type, items) in access_dict.items() {
                    for item in items {
                        if (type(item) == str) {
                            if bool(re.match(GROUP_PATTERN, item)) {
                                new_access[access_type].append({
                                    "group": item,
                                    "enabled": True
                                });
                            } elif(bool(re.match(USER_PATTERN, item))) {
                                new_access[access_type].append({
                                    "user": item,
                                    "enabled": True
                                });
                            }
                        } else {
                            new_access[access_type].append(item);
                        }
                    }
                }
                new_permissions[permission_type][resource] = new_access;
            }
        }

        return new_permissions;
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
        groups = self.get_groups(include_users=True, group=group_names);
        for name in group_names {
            for group in groups {
                if(session_id in group['users'] and group['name'] == name) {
                    return True;
                }
            }
        }

        return False;
    }

    can healthcheck() -> Union[dict, bool] {
        try {
            permissions = self.export_permissions().permissions;
            USER_PATTERN = r'^(\d{10,15}|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$';
            GROUP_PATTERN = r'^[a-zA-Z_][a-zA-Z0-9_]*(_[a-zA-Z0-9_]+)*$';

            if (type(permissions) != dict or permissions == {}) {
                message = f"permissions is not a dict or is empty {type(permissions)}";
                return { "status": False, "severity": "error", "message": message };
            }
            
            for channel in permissions {
                resources = permissions[channel];
                if (type(resources) != dict) {
                    message = f"permissions resources for channel {channel} is not a dict";
                    return {"status": False, "severity": "error", "message": message };
                }
                
                for (resource, access_dict) in resources.items() {
                    if (type(access_dict) != dict) {
                        message = f"permissions access dict for resource {resource} is not a dict";
                        return { "status": False, "severity": "error", "message": message };
                    }
                    
                    if ("allow" not in access_dict or "deny" not in access_dict) {
                        message = f"permissions access dict for resource {resource} does not contain allow or deny";
                        return { "status": False, "severity": "error", "message": message };
                    }

                    allow_list = access_dict["allow"];
                    deny_list = access_dict["deny"];
                    
                    if (not isinstance(allow_list, list) or not isinstance(deny_list, list)) {
                        message = f"permissions allow or deny list for resource {resource} is not a list.";
                        return { "status": False, "severity": "error", "message": message };
                    }
                    
                    for item in allow_list {
                        for key in item.keys() {
                            if (key not in ["enabled", "user", "group"]) {
                                message = f"permissions allow list for resource {resource} contains invalid key {key}";
                                return { "status": False, "severity": "error", "message": message };
                            }elif(key == "enabled" and type(item[key]) != bool) {
                                message = f"permissions allow list for resource {resource} enabled key is not a bool";
                                return { "status": False, "severity": "error", "message": message };
                            }elif(key == "user" and not bool(re.match(USER_PATTERN, item[key]))) {
                                message = f"permissions allow list for resource {resource} have invalid user {item[key]}";
                                return { "status": False, "severity": "error", "message": message };
                            }elif(key == "group" and not bool(re.match(GROUP_PATTERN, item[key]))) {
                                message = f"permissions allow list for resource {resource} have invalid group {item[key]}";
                                return { "status": False, "severity": "error", "message": message };
                            }
                        }
                    }
                    
                    for item in deny_list {
                        for key in item.keys() {
                            if (key not in ["enabled", "user", "group"]) {
                                message = f"permissions deny list for resource {resource} contains invalid key {key}";
                                return { "status": False, "severity": "error", "message": message };
                            }elif(key == "enabled" and type(item[key]) != bool) {
                                message = f"permissions deny list for resource {resource} enabled key is not a bool";
                                return { "status": False, "severity": "error", "message": message };
                            }elif(key == "user" and not bool(re.match(USER_PATTERN, item[key]))) {
                                message = f"permissions deny list for resource {resource} have invalid user {item[key]}";
                                return { "status": False, "severity": "error", "message": message };
                            }elif(key == "group" and not bool(re.match(GROUP_PATTERN, item[key]))) {
                                message = f"permissions deny list for resource {resource} have invalid group {item[key]}";
                                return { "status": False, "severity": "error", "message": message };
                            }
                        }
                    }
                }
            }
            return True;
        } except Exception as e {
            return { "status": False, "severity": "error", "message": f"An error occurred: {e}" };
        }
    }

    can import_permissions(permissions:dict={}, session_groups:dict={}, purge_collection:bool=True) -> bool {
        # pruge collection before migration

        if not permissions {
            return False;
        }
        # convert permissions to new format
        permissions = self.convert_permissions(permissions);
        self.permissions = permissions;

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

            for permission_resource in permissions[permission_channel] {
                if last_channel != permission_channel {
                    # add new resource to channel
                    resource = (collection spawn _add_resource(name=permission_resource, new_resource=True)).resource;
                    channel ++> resource;
                }
                # get allow and deny permissions
                permission_resource_allow = list(permissions[permission_channel][permission_resource]["allow"]);
                permission_resource_deny = list(permissions[permission_channel][permission_resource]["deny"]);

                # add allow permissions
                for item in permission_resource_allow {
                    if ( "name" in item ) {
                        if last_resource != permission_resource {
                            # add group to collection
                            group = (collection spawn _add_group(name=item['name'], new_group=True)).group;
                            resource +:Allow:enabled=item["enabled"]:+> group;
                        }
                    } elif ( "user" in item ) {
                        if last_resource != permission_resource {
                            # add user to collection
                            user = (collection spawn _add_user(user_id=item["user"], new_user=True)).user;
                            resource +:Allow:enabled=item["enabled"]:+> user;
                        }
                    }
                }

                # add deny permissions
                for item in permission_resource_deny {
                    # check if item in both allow and deny
                    if(item not in permission_resource_allow) {
                        if ( "group" in item ) {
                            if last_resource != permission_resource {
                                # add group to collection
                                group = (collection spawn _add_group(name=item['group'], new_group=True)).group;
                                resource +:Deny:enabled=item["enabled"]:+> group;
                            }
                        } elif( "user" in item ) {
                            if last_resource != permission_resource {
                                # add user to collection
                                user = (collection spawn _add_user(user_id=item["user"], new_user=True)).user;
                                resource +:Deny:enabled=item["enabled"]:+> user;
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
            for user in session_groups[session_group] {
                self.add_user_to_group(session_group, user);
            }
        }
        return True;
    }

    can export_permissions() -> dict {
        collection = self.get_collection();
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

            result = (collection spawn _has_access(user_id=session_id, channel=channel, resource=action_label)).access;
            return result;
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
                if ( bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', user_id)) or user_id == "any" ) {
                    group_result = (collection spawn _add_group(name=user_id, parent_node=resource_result.resource.id));
                    # delete existing edges and add new edge
                    resource_result.resource del -:Allow:-> group_result.group;
                    resource_result.resource del -:Deny:-> group_result.group;
                    resource_result.resource +:Allow:+> group_result.group;
                } elif( bool(re.match(r'^\d+$', user_id)) or user_id == "any" ) {
                    user_result = (collection spawn _add_user(user_id=user_id, parent_node=resource_result.resource.id));
                    # delete existing edges and add new edge
                    resource_result.resource del -:Deny:-> user_result.user;
                    resource_result.resource del -:Allow:-> user_result.user;
                    resource_result.resource +:Allow:+> user_result.user;
                }
            } else {
                if ( bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', user_id)) or user_id == "any" ) {
                    group_result = (collection spawn _add_group(name=user_id, parent_node=resource_result.resource.id));
                    # delete existing edges and add new edge
                    resource_result.resource del -:Allow:-> group_result.group;
                    resource_result.resource del -:Deny:-> group_result.group;
                    resource_result.resource +:Deny:+> group_result.group;
                } elif( bool(re.match(r'^\d+$', user_id)) or user_id == "any" ) {
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

    can delete_permission(channel:str="", resource:str="", group:str="", user_id:str="") -> bool {
        collection = self.get_collection();
        return (collection spawn _delete_permission(channel=channel, resource=resource, group=group, user_id=user_id)).deleted;
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

    can get_groups(group:str="", include_users:bool=False) -> list {
        collection = self.get_collection();
        return (collection spawn _get_groups(group=group, include_users=include_users)).groups;
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
        visit [-->](`?Users);
    }

    can on_users with Users entry {
        visit [-->](`?User)(?user_id == self.user_id);
    }

    can on_user with User entry {
        parent_nodes = [<--];
        if self.group {
            if(len(parent_nodes) <= 2) {
                self.deleted = True;
                Jac.destroy(here);
            }else{
                here del <-- [<--](`?Group)(?name == self.group);
            }
        }else{
            self.deleted = True;
            Jac.destroy(here);
        }

    }
}

walker _delete_permission {
    has channel:str = "";
    has resource:str = "";
    has group:str = "";
    has user_id:str = "";
    has deleted:list = [];

    can on_collection with Collection entry {
        visit [-->](`?Channels);
    }

    can on_channels with Channels entry {
        visit [-->](`?Channel)(?name == self.channel);
    }

    can on_channel with Channel entry {
        visit [-->](`?Resource)(?name == self.resource);
    }

    can on_resource with Resource entry {

        parent_edges = [<--];
        children_edges = [<--];
        if(len(parent_edges) <= 2 and len(children_edges) <= 1) {
            here del <-- [<--](`?Channel)(?name == self.channel);
            self.deleted.append(here);

        }

        visit [-->](`?Group)(?name == self.group) else {
            visit [-->](`?User)(?user_id == self.user_id);
        }
    }

    can on_group with Group entry {
        here del <-- [<--](`?Resource)(?name == self.resource);
        self.deleted.append(here);
    }

    can on_user with User entry {
        here del <-- [<--](`?Resource)(?name == self.resource);
        self.deleted.append(here);
    }

}

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
    has group:str = "";
    has include_users:bool = False;

    can on_collection with Collection entry {
        visit [-->](`?Groups);
    }

    can on_groups with Groups entry {
        if self.group {
            visit [-->](`?Group)(?name == self.group);
        }else{
            visit [-->](`?Group);
        }
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

        allow_nodes_disabled = [-:Allow:enabled==False:->];
        allow_nodes_enabled = [-:Allow:enabled==True:->];
        deny_nodes_enabled = [-:Deny:enabled==True:->];
        deny_nodes_disabled = [-:Deny:enabled==False:->];


        for allow_node in allow_nodes_enabled {
            if allow_node.get_type() in ["Group", "AnyGroup"] {
                allow_list.append({"name": allow_node.name, "enabled": True});
            }else{
                allow_list.append({"user": allow_node.user_id, "enabled": True});
            }
        }

        for allow_node in allow_nodes_disabled {
            if allow_node.get_type() in ["Group", "AnyGroup"] {
                allow_list.append({"name": allow_node.name, "enabled": False});
            }else{
                allow_list.append({"user": allow_node.user_id, "enabled": False});
            }
        }


        for deny_node in deny_nodes_enabled {
            if deny_node.get_type() in ["Group", "AnyGroup"] {
                deny_list.append({"name": deny_node.name, "enabled": True});
            }else{
                deny_list.append({"user": deny_node.user_id, "enabled": True});
            }
        }


        for deny_node in deny_nodes_disabled {
            if deny_node.get_type() in ["Group", "AnyGroup"] {
                deny_list.append({"name": deny_node.name, "enabled": False});
            }else{
                deny_list.append({"user": deny_node.user_id, "enabled": False});
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


walker _has_access {
    has channel:str = "default";
    has resource:str = "any";
    has user_id:str = "all";
    has access:bool = False;
    has denied_groups:list = [];

    obj __specs__ {
        static has private:bool = True;
    }

    can on_collection with Collection entry {
        # we deny by default
        self.access = False;
        # set default values
        if not self.user_id {
            self.user_id = "all";
        }
        if not self.resource {
            self.user_id = "any";
        }
        visit [-->](`?Channels);
    }

    can on_channels with Channels entry {
        visit [-->](`?Channel)(?name==self.channel);
    }

    can on_channel with Channel entry {
        # set another walker on the explicit deny traversal check
        result = (here spawn _has_explicit_deny_access(
            resource = self.resource,
            user_id = self.user_id
        ));
        self.denied_groups = result.groups;

        if result.denied {
            self.access = False;
            if not self.denied_groups {
                disengage;
            }
        }


        visit [-->](`?Resource)(?name==self.resource) else {
            visit [-->](`?Resource)(?name=="any");
        }
    }

    can on_resource with Resource entry {
        visit [-:Allow:enabled==True:->](`?User)(?user_id==self.user_id) else {
            visit [-:Allow:enabled==True:->](`?Group);
        }
    }

    can on_user with User entry {
        self.access = True;
    }


    can on_group with Group entry {
        visit [-->](`?User)(?user_id==self.user_id) else {
            if isinstance(here, AnyGroup) and not self.denied_groups {
                self.access = True;
            }
        }
    }

}


walker _has_explicit_deny_access {

    has resource:str = "any";
    has user_id:str = "all";
    has denied:bool = False;
    has groups:list = [];

    obj __specs__ {
        static has private:bool = True;
    }

    can on_channel with Channel entry {
        visit [-->](`?Resource)(?name==self.resource) else {
            visit [-->](`?Resource)(?name=="any");
        }
    }

    can on_resource with Resource entry {
        visit [-:Deny:enabled==True:->](`?User)(?user_id==self.user_id) else {
            visit [-:Deny:enabled==True:->](`?Group);
        }
    }

    can on_user with User entry {
        self.denied = True;
    }

    can on_group with Group entry {

        if [-->](`?User)(?user_id==self.user_id){
            self.groups.append(here.get_type());
            visit [-->](`?User)(?user_id==self.user_id);
        } elif (isinstance(here, AnyGroup)) {
            self.groups.append(here.get_type());
            self.denied = True;
        }
    }
}


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
        visit [-->](`?Channels);
    }
    can on_channels with Channels entry {
        visit [-->](`?Channel)(?name==self.channel);
    }
    can on_channel with Channel entry {
        visit [-->](`?Resource)(?name==self.resource);
    }
    can on_resource with Resource entry {
        allow_user_edges = [-:Allow:->](`?User)(?user_id==self.user);
        deny_user_edges = [-:Deny:->](`?User)(?user_id==self.user);
        allow_group_edges = [-:Allow:->](`?Group)(?name==self.user);
        deny_group_edges = [-:Deny:->](`?Group)(?name==self.user);


        if allow_user_edges {
            here del --> [-->](`?User)(?user_id == allow_user_edges[0].user_id);
            here +:Allow:enabled=self.enabled:+> allow_user_edges[0];
        }

        if deny_user_edges {
            here del --> [-->](`?User)(?user_id == deny_user_edges[0].user_id);
            here +:Deny:enabled=self.enabled:+> deny_user_edges[0];
        }

        if allow_group_edges {
            here del --> [-->](`?Group)(?name == allow_group_edges[0].name);
            here +:Allow:enabled=self.enabled:+> allow_group_edges[0];
        }

        if deny_group_edges {
            here del --> [-->](`?Group)(?name == deny_group_edges[0].name);
            here +:Deny:enabled=self.enabled:+> deny_group_edges[0];
        }

        self.result = True;
    }
}
