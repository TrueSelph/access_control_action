# Access Control Action

Allows access control permissions to be defined per action and user (by session_id); maintains a record of session_ids and associated role. 

## Package Information

- **Name:** jivas/access_control_action  
- **Author:** V75 Inc.  
- **Architype:** AccessControlAction  
- **Version:** 0.0.1  

## Meta Information  

- **Title:** Access Control Action   
- **Group:** core  
- **Type:** action  

## Configuration  

- **Singleton:** true  

## Dependencies  

- **Jivas:** ^2.0.0  

This package enables granular control over permissions for actions performed by users within the system. Permissions can be finely tuned based on specific session IDs or logically-defined groups of sessions. It maintains permission configurations and roles tied explicitly to each user session. The action type is configured as a singleton, ensuring only one active instance exists at any given time to guarantee consistency in permission checks throughout the platform.

---

## How to Configure Permissions  

Below is detailed guidance on how to configure the access control permissions.  

### Overview  

The access control configuration allows you to specify permissions along multiple dimensions, enabling or restricting specific actions based on:  
- Communication **channels** (e.g. WhatsApp, SMS, email, default)  
- Specific **actions/resources** (e.g. sending messages, subscribing to content; defaults to `"any"`)  
- Individual **session IDs** (unique identifiers for users or agents)  
- **Session groups** (logical groups of users you define)  

---

### Configuration Structure  

The configuration consists of three primary components:

#### `permissions`  

Defines the allow or deny settings for channels, resources, actions, or default rules.  

```python
permissions = {
    "channel": {                # Example: "default", "whatsapp", "sms"
        "resource/action": {    # Specific action/resource or default to "any"
            "deny": [],         # List restricted session_ids, session_groups, or keyword "all"
            "allow": []         # List allowed session_ids, session_groups, or keyword "all"
        }
    }
}
```

#### Special Keywords  
- `"any"` applies rules as default across all undefined specific actions/resources.
- `"all"` conveniently refers to all sessions/users.

#### `session_groups`

Define logical collections of session IDs for easier permission management.

```python
session_groups = {
    "admins": ["session123", "session456"],
    "support_team": ["session789", "session101"]
}
```

#### `exceptions`

Define actions exempted from permissions checks and allowed unrestricted access.

```python
exceptions = ["action_name", "another_action_name"]
```

If listed, these actions ignore any permissions limitation configured within the `permissions` block.

---

### Example Configurations  

#### Allowing everyone all actions on default channel  

```python
permissions = {
    "default": {
        "any": {
            "deny": [],
            "allow": ["all"]
        }
    }
}
```

#### Restricting a specific action/channel to an admin group  

```python
permissions = {
    "default": {
        "delete_resource": {
            "deny": ["all"],
            "allow": ["admins"]
        }
    }
}

session_groups = {
    "admins": ["session_id_1", "session_id_2"]
}
```

#### Allowing a specific action only for one session/user ID  

```python
permissions = {
    "whatsapp": {
        "send_message": {
            "deny": ["all"],
            "allow": ["session_xyz"]
        }
    }
}
```

#### Allowing exceptions  

```python
exceptions = ["system_healthcheck"]
```

The above example shows that permission limitations will not apply to the specified `"system_healthcheck"` action.

---

### Best Practices  
- Clearly define `session_groups` to simplify permission management at scale.  
- Define global permissions broadly (`"any"`) before fine-tuning for specific actions.  
- Keep your `exceptions` minimal to maintain security and integrity.

---

### Applying Configuration Updates  
After updating the configuration (`permissions`, `session_groups`, `exceptions`):

- Validate your changes carefully.
- Deploy configurations to a testing environment before production rollout.
- Consider periodic auditing of your permission configurations to maintain proper security standards.

---

### Troubleshooting  
- Always verify your session IDs and group memberships.
- Double-check syntax and correct usage of special keywords (`"any"`, `"all"`).
- Note explicitly stated `"deny"` permissions always override allowed ones when permission conflicts arise.

---

### Summary  
Properly configuring permissions using the Access Control Action ensures your platform remains secure by restricting actions based on clearly defined, configurable rules. It provides a robust mechanism to address diverse security and operational needs across users, actions, and communication channels.