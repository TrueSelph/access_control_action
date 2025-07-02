# Access Control Action

![GitHub release (latest by date)](https://img.shields.io/github/v/release/TrueSelph/access_control_action)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/TrueSelph/access_control_action/test-access_control_action.yaml)
![GitHub issues](https://img.shields.io/github/issues/TrueSelph/access_control_action)
![GitHub pull requests](https://img.shields.io/github/issues-pr/TrueSelph/access_control_action)
![GitHub](https://img.shields.io/github/license/TrueSelph/access_control_action)

Allows access control permissions to be defined per action and user `(by session_id);` maintains a record of session_ids and associated role.

## Package Information

- **Name:** jivas/access_control_action
- **Author:** V75 Inc.
- **Architype:** AccessControlAction
- **Version:** 0.1.0

## Meta Information

- **Title:** Access Control Action
- **Group:** core
- **Type:** action

## Configuration

- **Singleton:** true

## Dependencies

- **Jivas:** `^2.1.0`

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

### `permissions`

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

### Special Keywords
- `"any"` applies rules as default across all undefined specific actions/resources.
- `"all"` conveniently refers to all sessions/users.

### `session_groups`

Define logical collections of session IDs for easier permission management.

```python
session_groups = {
    "admins": ["session123", "session456"],
    "support_team": ["session789", "session101"]
}
```

### `exceptions`

Define actions exempted from permissions checks and allowed unrestricted access.

```python
exceptions = ["action_name", "another_action_name"]
```

If listed, these actions ignore any permissions limitation configured within the `permissions` block.

## Example Configurations

### Allowing everyone all actions on default channel

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

### Restricting a specific action/channel to an admin group

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

### Allowing a specific action only for one session/user ID

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

### Allowing exceptions

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

## 🔰 Contributing

- **🐛 [Report Issues](https://github.com/TrueSelph/access_control_action/issues)**: Submit bugs found or log feature requests for the `access_control_action` project.
- **💡 [Submit Pull Requests](https://github.com/TrueSelph/access_control_action/blob/main/CONTRIBUTING.md)**: Review open PRs, and submit your own PRs.

<details closed>
<summary>Contributing Guidelines</summary>

1. **Fork the Repository**: Start by forking the project repository to your GitHub account.
2. **Clone Locally**: Clone the forked repository to your local machine using a git client.
   ```sh
   git clone https://github.com/TrueSelph/access_control_action
   ```
3. **Create a New Branch**: Always work on a new branch, giving it a descriptive name.
   ```sh
   git checkout -b new-feature-x
   ```
4. **Make Your Changes**: Develop and test your changes locally.
5. **Commit Your Changes**: Commit with a clear message describing your updates.
   ```sh
   git commit -m 'Implemented new feature x.'
   ```
6. **Push to GitHub**: Push the changes to your forked repository.
   ```sh
   git push origin new-feature-x
   ```
7. **Submit a Pull Request**: Create a PR against the original project repository. Clearly describe the changes and their motivations.
8. **Review**: Once your PR is reviewed and approved, it will be merged into the main branch. Congratulations on your contribution!
</details>

<details open>
<summary>Contributor Graph</summary>
<br>
<p align="left">
    <a href="https://github.com/TrueSelph/access_control_action/graphs/contributors">
        <img src="https://contrib.rocks/image?repo=TrueSelph/access_control_action" />
   </a>
</p>
</details>

## 🎗 License

This project is protected under the Apache License 2.0. See [LICENSE](./LICENSE) for more information.