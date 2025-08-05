"""This module contains the render function for the access control action app."""

import json
import time
from contextlib import suppress

import pandas as pd
import streamlit as st
import yaml
from jvclient.lib.utils import call_api, get_reports_payload
from jvclient.lib.widgets import app_controls, app_header, app_update_action
from streamlit_router import StreamlitRouter


def render(router: StreamlitRouter, agent_id: str, action_id: str, info: dict) -> None:
    """
    Render the access control action app.

    Args:
        router (StreamlitRouter): The router instance.
        agent_id (str): The agent ID.
        action_id (str): The action ID.
        info (dict): Additional information.
    """
    # add app header controls
    (model_key, module_root) = app_header(agent_id, action_id, info)

    with st.expander("Access Control Configuration", expanded=False):
        # Add main app controls
        app_controls(agent_id, action_id, hidden=["session_groups", "permissions"])
        # Add update button to apply changes
        app_update_action(agent_id, action_id)

    with st.expander("Export Permissions", False):
        if st.button(
            "Export Permissions",
            key=f"{model_key}_btn_export_permissions",
            disabled=(not agent_id),
        ):
            # Call the function to purge
            if result := call_api(
                endpoint="action/walker/access_control_action/export_permissions",
                json_data={"agent_id": agent_id},
            ):
                st.success("Export permissions successfully")
                if result and result.status_code == 200:
                    report_result = get_reports_payload(result)
                    st.download_button(
                        label="Download Exported Permissions",
                        data=json.dumps(report_result, indent=2),
                        file_name="exported_permissions.json",
                        mime="application/json",
                    )
                    st.json(report_result)
            else:
                st.error(
                    "Failed to export permissions. Ensure that there is something to export"
                )

    with st.expander("Import Permissions", False):
        permission_source = st.radio(
            "Choose data source:",
            ("Text input", "Upload file"),
            key=f"{model_key}_permissions_source",
        )

        raw_text_input = ""
        uploaded_file = None
        data_to_import = None

        if permission_source == "Text input":
            raw_text_input = st.text_area(
                "Permissions in YAML or JSON",
                value="",
                height=170,
                key=f"{model_key}_permissions_data",
            )

        if permission_source == "Upload file":
            uploaded_file = st.file_uploader(
                "Upload file (YAML or JSON)",
                type=["yaml", "json"],
                key=f"{model_key}_agent_permissions_upload",
            )

        purge_collection = st.checkbox(
            "Purge Collection", value=False, key=f"{model_key}_purge_collection"
        )

        if st.button(
            "Import Permissions",
            key=f"{model_key}_btn_import_permissions",
            disabled=(not agent_id),
        ):
            try:
                if permission_source == "Upload file" and uploaded_file:
                    file_content = uploaded_file.read().decode("utf-8")
                    if uploaded_file.type == "application/json":
                        data_to_import = json.loads(file_content)
                    else:
                        data_to_import = yaml.safe_load(file_content)

                elif permission_source == "Text input" and raw_text_input.strip():
                    # Try JSON first, fall back to YAML
                    try:
                        data_to_import = json.loads(raw_text_input)
                    except json.JSONDecodeError:
                        data_to_import = yaml.safe_load(raw_text_input)

                if data_to_import is None:
                    st.error("No valid permissions data provided.")
                else:
                    permissions = {}
                    session_groups = {}
                    if (
                        "session_groups" in data_to_import
                        and "permissions" in data_to_import
                    ):
                        permissions = data_to_import["permissions"]
                        session_groups = data_to_import["session_groups"]
                    else:
                        permissions = data_to_import

                    result = call_api(
                        endpoint="action/walker/access_control_action/import_permissions",
                        json_data={
                            "agent_id": agent_id,
                            "permissions": permissions,
                            "session_groups": session_groups,
                            "purge_collection": purge_collection,
                        },
                    )
                    if result:
                        st.success("Import permissions successfully")
                    else:
                        st.error(
                            "Failed to import permissions. Ensure that there is something to import."
                        )
            except Exception as e:
                st.error(f"Import failed: {e}")

    with st.expander("Manage Users", False):
        add_tab, users_tab = st.tabs(["Add Users", "Users"])

        # add user tab
        with add_tab:
            # Create the text input - let Streamlit manage the state with the key
            user_id = st.text_input("Enter User ID", key=f"{model_key}_input_user_id")

            if st.button(
                "Add User", key=f"{model_key}_btn_add_user", disabled=(not agent_id)
            ):
                if result := call_api(
                    endpoint="action/walker/access_control_action/add_user",
                    json_data={"agent_id": agent_id, "user_id": user_id},
                ):
                    st.success("User added successfully")
                else:
                    st.error("Failed to add user. Ensure that the user ID is correct")

                time.sleep(2)
                st.rerun()

        # users tab
        with users_tab:

            st.markdown(
                """
            <style>
                .slim-row {
                    padding: 0.5rem 0;
                    border-bottom: 1px solid #e0e0e0;
                }
                .slim-row:last-child {
                    border-bottom: none;
                }
                .compact-button {
                    padding: 0.2em 0.5em;
                    font-size: 0.9em;
                    height: auto !important;
                }
            </style>
            """,
                unsafe_allow_html=True,
            )

            if result := call_api(
                endpoint="action/walker/access_control_action/get_users",
                json_data={"agent_id": agent_id},
            ):
                result = get_reports_payload(result)
                for user in result:
                    # Create a container for each row with custom class
                    with st.container():
                        # Add custom class to the container
                        st.markdown('<div class="slim-row">', unsafe_allow_html=True)

                        user_id = user['context']['user_id']

                        cols = st.columns([4, 1])
                        with cols[0]:
                            st.markdown(f"**{user_id}**")

                        with cols[1]:
                            if st.button(
                                "Delete",
                                key=f"{model_key}_{user_id}_btn_delete_user",
                                disabled=(not agent_id),
                                # Use compact button style
                                use_container_width=True,
                            ):
                                if result := call_api(
                                    endpoint="action/walker/access_control_action/delete_user",
                                    json_data={"agent_id": agent_id, "user_id": user_id},
                                ):
                                    st.success(
                                        f"User {user_id} removed successfully"
                                    )
                                else:
                                    st.error(
                                        f"Failed to remove user '{user_id}'"
                                    )

                                time.sleep(2)
                                st.rerun()

                        # Close the div
                        st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.error("Failed to get user.")

    with st.expander("Manage Groups", False):
        add_tab, add_session_group_tab, groups_tab = st.tabs(
            ["Add Group", "Add User to Group", "Groups"]
        )

        with add_tab:
            new_group = st.text_input("Enter Group", key=f"{model_key}_input_group")
            if st.button("Add Group", key=f"{model_key}_btn_add_group"):
                # Call the function to purge
                if result := call_api(
                    endpoint="action/walker/access_control_action/add_group",
                    json_data={"agent_id": agent_id, "name": new_group},
                ):
                    st.success("Group added successfully")
                else:
                    st.error("Failed to add group. Ensure that the group is correct")

                time.sleep(2)
                st.rerun()

        with add_session_group_tab:
            groups_result = {} 
            groups_result_ = call_api(
                endpoint="action/walker/access_control_action/get_groups",
                json_data={"agent_id": agent_id, "include_users": True},
            )
            if groups_result_ and groups_result_.status_code == 200:
                groups_result = get_reports_payload(groups_result_)


            users_result_ = call_api(
                endpoint="action/walker/access_control_action/get_users", 
                json_data={"agent_id": agent_id}
            )
            users = []
            if users_result_ and users_result_.status_code == 200:
                users = get_reports_payload(users_result_)

            if groups_result:
                groups = groups_result.keys()
            else:
                groups = []

            users = [user["context"]["user_id"] for user in users]
            if not groups:
                st.error("Failed to get groups.")

            if not users:
                st.error("Failed to get users.")

            user_id = st.selectbox("Select User", users, key=f"{model_key}_select_user")
            group = st.selectbox(
                "Select Group", groups, key=f"{model_key}_select_group"
            )

            if st.button("Add User to Group", key=f"{model_key}_btn_add_session_group"):
                # Call the function to purge
                if result := call_api(
                    endpoint="action/walker/access_control_action/add_session_group",
                    json_data={"agent_id": agent_id, "user_id": user_id, "group": group},
                ):
                    st.success("Group added successfully")
                else:
                    st.error("Failed to add group. Ensure that the group is correct")
                time.sleep(2)
                st.rerun()

        with groups_tab:

            for group_name in groups_result:
                users = groups_result[group_name]
                if group_name not in ["all", "any"]:

                    # Group header row
                    group_cols = st.columns([6, 1])
                    with group_cols[0]:
                        st.markdown(f"### {group_name}")
                    with group_cols[1]:
                        if st.button(
                            "Delete Group",
                            key=f"{model_key}_{group_name}_btn_delete_group",
                            disabled=(not agent_id),
                            use_container_width=True,
                        ):
                            result = call_api(
                                endpoint="action/walker/access_control_action/delete_group",
                                json_data={"agent_id": agent_id, "name": group_name},
                            )
                            if result:
                                st.success(f"Group {group_name} removed successfully")
                            else:
                                st.error(f"Failed to remove group '{group_name}'")
                            time.sleep(2)
                            st.rerun()

                    # Show users under group
                    if users:
                        for i, user in enumerate(users):
                            # Alternate background color
                            bg_color = "#1f1f23" if i % 2 == 0 else "#2a2a2f"
                            text_color = "#817D7D"

                            user_cols = st.columns([6, 1])
                            with user_cols[0]:
                                st.markdown(
                                    f"""
                                    <div style="padding: 10px 14px;
                                                background-color: {bg_color};
                                                border-radius: 8px;
                                                margin-bottom: 6px;
                                                border: 1px solid #3c3c3c;">
                                        <strong style="color: {text_color}; font-size: 15px;">{user}</strong>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )

                            with user_cols[1]:
                                if st.button(
                                    "Remove User",
                                    key=f"del_user_{group_name}_{user}",
                                    use_container_width=True,
                                    help=f"Remove {user} from {group_name}",
                                ):
                                    result = call_api(
                                        endpoint="action/walker/access_control_action/remove_user",
                                        json_data={
                                            "agent_id": agent_id,
                                            "group": group_name,
                                            "user_id": user,
                                        },
                                    )

                                    if result:
                                        st.success(
                                            f"User '{user}' removed from '{group_name}'"
                                        )

                                        with suppress(Exception):
                                            st.experimental_rerun()
                                    else:
                                        st.error(
                                            f"Failed to remove user '{user}' from '{group_name}'"
                                        )

                                    time.sleep(2)
                                    st.rerun()
                    else:
                        st.info("No users in this group.")
            st.markdown("\n")

    with st.expander("Manage Permissions", expanded=False):
        st.subheader("Add Permissions")
        # Channel selection
        channels = []
        channels_result_ = call_api(
            endpoint="action/walker/access_control_action/get_channels",
            json_data={"agent_id": agent_id})
        
        if channels_result_ and channels_result_.status_code == 200:
            channels = get_reports_payload(channels_result_)


        if channels:
            channel = st.selectbox(
                "Channels", channels, key=f"{model_key}_select_channels"
            )
        else:
            channel = ""
            st.warning("Channels not found")

        # Resource selection
        resources = []
        resources_result_ = call_api(endpoint="action/walker/access_control_action/get_resources", json_data={"agent_id": agent_id})
        if resources_result_ and resources_result_.status_code == 200:
            resources = get_reports_payload(resources_result_)

        if resources:
            resource = st.selectbox(
                "Resource", resources, key=f"{model_key}_select_resources"
            )
        else:
            resource = ""
            st.warning("Resources not found")

        # group selection
        groups_result = {}
        groups_result_ = call_api(
            endpoint="action/walker/access_control_action/get_groups",
            json_data={"agent_id": agent_id, "include_users": True},
        )
        if groups_result_ and groups_result_.status_code == 200:
            groups_result = get_reports_payload(groups_result_)

        if groups_result:
            groups = list(groups_result.keys())
        else:
            groups = []
            st.warning("Groups not found")

        # user selection
        users = []
        users_result_ = call_api(endpoint="action/walker/access_control_action/get_users", json_data={"agent_id": agent_id})
        if users_result_ and users_result_.status_code == 200:
            users = get_reports_payload(users_result_)

        if users:
            users_ids = [user["context"]["user_id"] for user in users]
            groups.extend(users_ids)

        if groups:
            user_id = st.selectbox(
                "Entity", groups, key=f"{model_key}_select_groups_and_users"
            )
        else:
            user_id = ""
            st.warning("Groups and Users not found")

        access = st.selectbox(
            "Access", ["allow", "deny"], key=f"{model_key}_select_access"
        )

        # Submit handler
        if st.button("Add Permission", key=f"{model_key}_btn_add_permission"):

            # check if permission is valid before trying to create permission
            result_ = call_api(
                endpoint="action/walker/access_control_action/get_access",
                json_data={"agent_id": agent_id, "channel": channel, "resource": resource},
            )

            if result_ and result_.status_code == 200:
                result = get_reports_payload(result_)

            if result:
                allow_list = result.get("allow", [])
                deny_list = result.get("deny", [])

                allow_list_formatted = []
                deny_list_formatted = []
                allow_group = []
                deny_group = []

                for item in allow_list:
                    if "user_id" in item['context']:
                        allow_list_formatted.append(item['context']["user_id"])
                    else:
                        allow_list_formatted.append(item['context']["name"])
                        # append group user to allow list
                        if item['context']["name"] in groups_result:
                            allow_group.extend(groups_result[item['context']["name"]])

                for item in deny_list:
                    if "user_id" in item['context']:
                        deny_list_formatted.append(item['context']["user_id"])
                    else:
                        deny_list_formatted.append(item['context']["name"])
                        # append group user to deny list
                        if item['context']["name"] in groups_result:
                            deny_group.extend(groups_result[item['context']["name"]])

                if user_id in deny_group:
                    st.error(
                        "User is in a GROUP that already has ALLOW access to this resource"
                    )
                elif user_id in allow_group:
                    st.error(
                        "User is in a GROUP that already has DENY access to this resource"
                    )
                elif user_id in allow_list_formatted:
                    st.error("User already has ALLOW access to this resource")
                elif user_id in deny_list_formatted:
                    st.error("User already has DENY access to this resource")
                else:
                    access_result = call_api(
                        endpoint="action/walker/access_control_action/add_permission",
                        json_data={
                            "agent_id": agent_id,
                            "channel": channel,
                            "resource": resource,
                            "allow": access == "allow",
                            "entity": user_id,
                            "is_group": user_id in groups_result,
                        },
                    )

                    if access_result:
                        st.success("Update successfully")
                    else:
                        st.error("Failed to update permissions")

                    time.sleep(2)
                    st.rerun()

            else:
                access_result = call_api(
                    endpoint="action/walker/access_control_action/add_permission",
                    json_data={
                        "agent_id": agent_id,
                        "channel": channel,
                        "resource": resource,
                        "allow": access == "allow",
                        "entity": user_id,
                        "is_group": user_id in groups_result,
                    }
                )

                if access_result and access_result.status_code == 200:
                    st.success("Update successfully")
                else:
                    st.error("Failed to update permissions")

    with st.expander("Permissions", True):
        # Initialize and fetch permissions
        if permissions := call_api(
            endpoint="action/walker/access_control_action/export_permissions", json_data={"agent_id": agent_id}
        ):
            permissions = permissions.json()
            permissions = permissions.get("reports", [{}])[0]

            # Process permissions data
            formatted_permissions = []
            permissions = permissions.get("permissions", {})

            for channel, resources in permissions.items():
                for resource, access in resources.items():
                    allow_list = access.get("allow", [])
                    deny_list = access.get("deny", [])

                    for user in allow_list:
                        formatted_permissions.append(
                            {
                                "enabled": user.get("enabled", False),
                                "channel": channel,
                                "resource": resource,
                                "permission": "Allow",
                                "entity": user.get("group")
                                or user.get("user", "Unknown"),
                                "type": "group" if user.get("group") else "user",
                            }
                        )

                    for user in deny_list:
                        formatted_permissions.append(
                            {
                                "enabled": user.get("enabled", False),
                                "channel": channel,
                                "resource": resource,
                                "permission": "Deny",
                                "entity": user.get("group")
                                or user.get("user", "Unknown"),
                                "type": "group" if user.get("group") else "user",
                            }
                        )

            # Initialize session state with proper column handling
            columns = ["enabled", "channel", "resource", "permission", "entity", "type"]
            # Create empty DataFrame with all columns if no permissions exist
            st.session_state.df_permissions = pd.DataFrame(
                formatted_permissions if formatted_permissions else [], columns=columns
            )

            # Ensure all columns exist in session state
            required_columns = [
                "enabled",
                "channel",
                "resource",
                "permission",
                "entity",
            ]
            for col in required_columns:
                if col not in st.session_state.df_permissions:
                    st.session_state.df_permissions[col] = (
                        False if col == "enabled" else ""
                    )

            # Display header
            st.subheader("Permissions")

            # Create filter columns - safely handle empty states
            cols = st.columns([1, 1, 1])

            with cols[0]:
                # # Safely get resource options
                resource_options = []
                if "resource" in st.session_state.df_permissions:
                    resource_options = (
                        st.session_state.df_permissions["resource"].unique().tolist()
                    )

                resource_filter = st.multiselect(
                    "Resource:",
                    options=resource_options,
                    default=[],
                    disabled=len(resource_options) == 0,
                )

            with cols[1]:
                user_filter = st.text_input("User ID contains:")

            with cols[2]:
                permission_filter = st.selectbox(
                    "Permission:", options=["All", "Allow", "Deny"]
                )

            # Apply filters safely
            filtered_df = st.session_state.df_permissions.copy()

            if resource_filter and "resource" in filtered_df:
                filtered_df = filtered_df[filtered_df["resource"].isin(resource_filter)]

            if user_filter and "entity" in filtered_df:
                filtered_df = filtered_df[
                    filtered_df["entity"].str.contains(
                        user_filter, case=False, na=False
                    )
                ]

            if permission_filter != "All" and "permission" in filtered_df:
                filtered_df = filtered_df[
                    filtered_df["permission"] == permission_filter
                ]

            # Display table header
            if not filtered_df.empty:
                header_cols = st.columns([0.54, 0.6, 1.43, 0.9, 0.8, 0.5, 0.01])
                header_labels = [
                    "Enabled",
                    "Channel",
                    "Resource",
                    "Entity",
                    "Permission",
                    "Delete",
                ]

                for i, label in enumerate(header_labels):
                    with header_cols[i]:
                        st.write(f"**{label}**")

            if "checkbox_states" not in st.session_state:
                st.session_state.checkbox_states = {}

            # Create form for each row
            for idx, row in filtered_df.iterrows():
                row_key = f"row_{idx}"
                with st.form(key=row_key):
                    cols = st.columns([0.5, 0.7, 1.5, 1, 0.8, 0.5])

                    # Enabled checkbox
                    with cols[0]:
                        # button_text = "Enable ✅" if row['enabled'] else "Disable ⛔"
                        button_text = "✅" if row["enabled"] else "⛔"
                        enable_submitted = st.form_submit_button(
                            button_text, use_container_width=True
                        )

                    # Display row data with fallbacks
                    with cols[1]:
                        st.write(row.get("channel", "N/A"))
                    with cols[2]:
                        st.write(row.get("resource", "N/A"))
                    with cols[3]:
                        st.write(row.get("entity", "Unknown"))
                    with cols[4]:
                        st.write(row.get("permission", "N/A"))

                    # Delete button
                    with cols[5]:
                        delete_submitted = st.form_submit_button(
                            "🗑️", use_container_width=True
                        )

                    # Submit button for the form
                    if enable_submitted:

                        if row.get("type") == "group":
                            payload = {
                                "agent_id": agent_id,
                                "enabled": not bool(row.get("enabled")),
                                "channel": row.get("channel", ""),
                                "resource": row.get("resource", ""),
                                "group": row.get("entity", ""),
                                "user": "",
                            }
                        else:
                            payload = {
                                "agent_id": agent_id,
                                "enabled": not bool(row.get("enabled")),
                                "channel": row.get("channel", ""),
                                "resource": row.get("resource", ""),
                                "user": row.get("entity", ""),
                                "group": "",
                            }

                        if call_api(
                            endpoint="action/walker/access_control_action/enable_access",
                            json_data=payload,
                        ):
                            st.success("Updated successfully!")
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error("Failed to update permission")

                    # Handle actions
                    if delete_submitted:

                        if row.get("type") == "group":
                            payload = {
                                "agent_id": agent_id,
                                "channel": row.get("channel", ""),
                                "resource": row.get("resource", ""),
                                "user_id": "",
                                "group": row.get("entity", ""),
                            }
                        else:
                            payload = {
                                "agent_id": agent_id,
                                "channel": row.get("channel", ""),
                                "resource": row.get("resource", ""),
                                "user_id": row.get("entity", ""),
                                "group": "",
                            }

                        if call_api(
                            endpoint="action/walker/access_control_action/delete_permission", json_data=payload
                        ):

                            st.session_state.df_permissions = (
                                st.session_state.df_permissions.drop(idx)
                            )
                            st.success("Permission successfully removed!")
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error("Failed to delete permission")

            # Show record count
            st.caption(
                f"Showing {len(filtered_df)} of {len(st.session_state.df_permissions)} permissions"
            )

            # Handle empty state
            if st.session_state.df_permissions.empty:
                st.info("No permissions found")
            elif filtered_df.empty:
                st.warning("No permissions match your filters")
