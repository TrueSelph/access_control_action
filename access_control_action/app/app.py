"""This module contains the render function for the access control action app."""

import json
import time
from contextlib import suppress

import pandas as pd
import streamlit as st
import yaml
from jvcli.client.lib.utils import call_action_walker_exec
from jvcli.client.lib.widgets import app_controls, app_header, app_update_action
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
    # add app main controls
    # app_controls(agent_id, action_id)
    # app_update_action(agent_id, action_id)
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
            if result := call_action_walker_exec(
                agent_id, module_root, "export_permissions", {}
            ):
                st.success("Export permissions successfully")
                if result:
                    result = json.dumps(result, indent=2)
                    st.write(result)
                    st.download_button(
                        label="Download Exported Permissions",
                        data=result,
                        file_name="exported_permissions.json",
                        mime="application/json",
                    )
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

                    result = call_action_walker_exec(
                        agent_id,
                        module_root,
                        "import_permissions",
                        {
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

    with st.expander("Manage Users", False):
        st.subheader("Add User")
        user_id = st.text_input("Enter User ID", key=f"{model_key}_input_user_id")
        if st.button(
            "Add User", key=f"{model_key}_btn_add_user", disabled=(not agent_id)
        ):
            # Call the function to purge
            if result := call_action_walker_exec(
                agent_id, module_root, "add_user", {"user_id": user_id}
            ):
                st.success("User added successfully")
            else:
                st.error("Failed to add user. Ensure that the user ID is correct")

            time.sleep(2)
            st.rerun()

        st.markdown("\n")
        st.subheader("Users")

        if result := call_action_walker_exec(agent_id, module_root, "get_users", {}):
            for user in result:
                # Create a container for each row with custom class
                with st.container():
                    # Add custom class to the container
                    st.markdown('<div class="slim-row">', unsafe_allow_html=True)

                    cols = st.columns([4, 1])
                    with cols[0]:
                        st.markdown(f"**{user['user_id']}**")

                    with cols[1]:
                        if st.button(
                            "Delete",
                            key=f"{model_key}_{user['user_id']}_btn_delete_user",
                            disabled=(not agent_id),
                            # Use compact button style
                            use_container_width=True,
                        ):
                            if result := call_action_walker_exec(
                                agent_id,
                                module_root,
                                "delete_user",
                                {"user_id": user["user_id"]},
                            ):
                                st.success(
                                    f"User {user['user_id']} removed successfully"
                                )
                            else:
                                st.error(f"Failed to remove user '{user['user_id']}'")

                            time.sleep(2)
                            st.rerun()

                    # Close the div
                    st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.error("Failed to get user.")

    with st.expander("Manage Groups", False):
        st.subheader("Add Group")
        new_group = st.text_input("Enter Group", key=f"{model_key}_input_group")
        if st.button("Add Group", key=f"{model_key}_btn_add_group"):
            # Call the function to purge
            if result := call_action_walker_exec(
                agent_id, module_root, "add_group", {"name": new_group}
            ):
                st.success("Group added successfully")
            else:
                st.error("Failed to add group. Ensure that the group is correct")

            time.sleep(2)
            st.rerun()

        st.markdown("\n---")

        groups_result = call_action_walker_exec(
            agent_id, module_root, "get_groups", {"include_users": True}
        )
        users = call_action_walker_exec(agent_id, module_root, "get_users", {})

        groups = [group["name"] for group in groups_result]
        users = [user["user_id"] for user in users]
        if not groups:
            st.error("Failed to get groups.")

        if not users:
            st.error("Failed to get users.")

        st.subheader("Add User to Group")

        user_id = st.selectbox("Select User", users, key=f"{model_key}_select_user")
        group = st.selectbox("Select Group", groups, key=f"{model_key}_select_group")

        if st.button("Add User to Group", key=f"{model_key}_btn_add_user_to_group"):
            # Call the function to purge
            if result := call_action_walker_exec(
                agent_id,
                module_root,
                "add_user_to_group",
                {"group": group, "user_id": user_id},
            ):
                st.success("Group added successfully")
            else:
                st.error("Failed to add group. Ensure that the group is correct")
            time.sleep(2)
            st.rerun()

        st.markdown("\n---")
        st.subheader("Groups and Users")

        for item in groups_result:
            group_name = item.get("name", "Unnamed Group")
            users = item.get("users", [])
            if group_name not in ["all", "any"]:
                st.markdown("---")

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
                        result = call_action_walker_exec(
                            agent_id, module_root, "delete_group", {"name": group_name}
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
                                result = call_action_walker_exec(
                                    agent_id,
                                    module_root,
                                    "delete_user",
                                    {"group": group_name, "user_id": user},
                                )
                                st.write(result)
                                if result:
                                    st.success(
                                        f"User '{user}' removed from '{group_name}'"
                                    )
                                    # st.experimental_rerun()
                                    # try:
                                    #     st.experimental_rerun()
                                    # except Exception as e:
                                    #     # st.error(f"Rerun failed: {type(e).__name__}: {str(e)}")
                                    #     # import traceback
                                    #     # st.text(traceback.format_exc())
                                    #     pass
                                    # from contextlib import suppress
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

    with st.expander("Manage Permissions", True):
        # Initialize selections

        # Channel selection
        channels = call_action_walker_exec(agent_id, module_root, "get_channels", {})
        if not channels:
            st.write("Channels not found")
            return
        channel = st.selectbox("Channels", channels, key=f"{model_key}_select_channels")

        # Resource selection
        resources = call_action_walker_exec(agent_id, module_root, "get_resources", {})
        if not resources:
            st.write("Resources not found")
            return
        resource = st.selectbox(
            "Resource", resources, key=f"{model_key}_select_resources"
        )

        # group selection
        groups_result = call_action_walker_exec(
            agent_id, module_root, "get_groups", {"include_users": True}
        )
        if not groups_result:
            st.write("Groups not found")
            return
        groups = [group["name"] for group in groups_result]

        # user selection
        users = call_action_walker_exec(agent_id, module_root, "get_users", {})
        if not users:
            st.write("Users not found")
        groups.extend([user["user_id"] for user in users])

        user_id = st.selectbox(
            "Groups and Users", groups, key=f"{model_key}_select_groups_and_users"
        )

        # allow or deny
        access = st.selectbox(
            "Access", ["allow", "deny"], key=f"{model_key}_select_access"
        )

        # Submit handler
        if st.button("Add Permission", key=f"{model_key}_btn_add_permission"):

            result = call_action_walker_exec(
                agent_id,
                module_root,
                "get_access",
                {"channel": channel, "resource": resource},
            )

            if result:
                allow_list = result.get("allow", [])
                deny_list = result.get("deny", [])

                group_dict = {}
                for g in groups_result:
                    group_dict[g["name"]] = g["users"]

                allow_list_formatted = []
                deny_list_formatted = []
                allow_group = []
                deny_group = []

                for item in allow_list:
                    if "user_id" in item:
                        allow_list_formatted.append(item["user_id"])
                    else:
                        allow_list_formatted.append(item["name"])
                        # append group user to allow list
                        if item["name"] in group_dict:
                            allow_group.extend(group_dict[item["name"]])

                for item in deny_list:
                    if "user_id" in item:
                        deny_list_formatted.append(item["user_id"])
                    else:
                        deny_list_formatted.append(item["name"])
                        # append group user to deny list
                        if item["name"] in group_dict:
                            deny_group.extend(group_dict[item["name"]])

                # current_access = True if user_id in allow_list_formatted else False
                # current_access = bool(user_id in allow_list_formatted)
                current_access = user_id in allow_list_formatted
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
                    access_result = call_action_walker_exec(
                        agent_id,
                        module_root,
                        "add_permission",
                        {
                            "channel": channel,
                            "resource": resource,
                            "allow": current_access,
                            "user_id": user_id,
                        },
                    )

                    if access_result:
                        st.success("Update successfully")
                    else:
                        st.error("Failed to update permissions")

                    # time.sleep(2)
                    # st.rerun()
            else:
                access_result = call_action_walker_exec(
                    agent_id,
                    module_root,
                    "add_permission",
                    {
                        "channel": channel,
                        "resource": resource,
                        # "allow": True if access == "allow" else False,
                        "allow": access == "allow",
                        "user_id": user_id,
                    },
                )

                if access_result:
                    st.success("Update successfully")
                else:
                    st.error("Failed to update permissions")

                time.sleep(2)
                st.rerun()

    with st.expander("Permissions", True):
        # Initialize selections
        # Call the function to purge
        if permissions := call_action_walker_exec(
            agent_id, module_root, "export_permissions", {}
        ):
            formatted_permissions = []
            permissions = permissions["permissions"]

            for channel in permissions:
                for resource in permissions[channel]:

                    allow_list = permissions[channel][resource].get("allow", [])
                    deny_list = permissions[channel][resource].get("deny", [])

                    for user in allow_list:
                        formatted_permissions.append(
                            {
                                "enabled": True,
                                "channel": channel,
                                "resource": resource,
                                "permission": "Allow",
                                "user": user,
                            }
                        )

                    for user in deny_list:
                        formatted_permissions.append(
                            {
                                "enabled": False,
                                "channel": channel,
                                "resource": resource,
                                "permission": "Deny",
                                "user": user,
                            }
                        )

            # Initialize session state for tracking changes
            if "df_permissions" not in st.session_state:
                st.session_state.df_permissions = pd.DataFrame(formatted_permissions)
            if "last_changed" not in st.session_state:
                st.session_state.last_changed = None

            # Configure column types for better display
            column_config = {
                "enabled": st.column_config.CheckboxColumn(
                    "Enabled",
                    help="Whether the permission is active",
                    default=False,
                ),
                "channel": st.column_config.TextColumn(
                    "Channel",
                    help="Communication channel",
                    disabled=True,  # Make non-editable
                ),
                "resource": st.column_config.TextColumn(
                    "Resource",
                    help="Target resource",
                    disabled=True,  # Make non-editable
                ),
                "user": st.column_config.TextColumn(
                    "User", help="User ID or group", disabled=True  # Make non-editable
                ),
                "permission": st.column_config.SelectboxColumn(
                    "Permission",
                    help="Access level",
                    options=["Allow", "Deny"],
                    required=True,
                    disabled=True,  # Make non-editable
                ),
            }

            # --- FILTERS SECTION ABOVE TABLE ---
            st.subheader("Permissions")

            # Create filter columns
            cols = st.columns([1, 1, 1])
            with cols[0]:
                channel_filter = st.multiselect(
                    "Channel:",
                    options=st.session_state.df_permissions["channel"].unique(),
                    default=st.session_state.df_permissions["channel"].unique(),
                )

            with cols[1]:
                user_filter = st.text_input("User ID contains:")

            with cols[2]:
                permission_filter = st.selectbox(
                    "Permission:", options=["All", "Allow", "Deny"]
                )

            # Apply filters
            filtered_df = st.session_state.df_permissions.copy()
            if channel_filter:
                filtered_df = filtered_df[filtered_df["channel"].isin(channel_filter)]
            if user_filter:
                filtered_df = filtered_df[
                    filtered_df["user"].str.contains(user_filter, case=False)
                ]
            if permission_filter != "All":
                filtered_df = filtered_df[
                    filtered_df["permission"] == permission_filter
                ]

            # --- TABLE SECTION WITH INTERACTIVE CHECKBOXES ---
            # st.subheader("Permissions Configuration")

            # Use data editor for interactive checkboxes
            edited_df = st.data_editor(
                filtered_df,
                column_config=column_config,
                use_container_width=True,
                hide_index=True,
                height=700,
                key="permissions_editor",
            )

            # Detect changes and show modified row
            if not edited_df.equals(filtered_df):
                # Find changed rows
                changed_rows = edited_df[edited_df["enabled"] != filtered_df["enabled"]]

                if not changed_rows.empty:
                    # Update session state with changes
                    for idx, row in changed_rows.iterrows():
                        st.session_state.df_permissions.loc[idx, "enabled"] = row[
                            "enabled"
                        ]

                    # Store last changed row for display
                    st.session_state.last_changed = changed_rows.iloc[0].to_dict()

                    # Show success message
                    # st.success("Permissions updated!")

                    # Print changed row to console (and display in app)
                    # st.write("Last changed row:")
                    # st.json(st.session_state.last_changed)

                    # Print to terminal (for actual console printing)
                    print("Changed row:", st.session_state.last_changed)
                    # {"enabled":true,"channel":"whatsapp","resource":"ListAvailableCoursesInteractAction","permission":"Deny","user":"test"}
                    enable_result = st.session_state.last_changed
                    if call_action_walker_exec(
                        agent_id,
                        module_root,
                        "enable_access",
                        {
                            "enabled": enable_result["enabled"],
                            "channel": enable_result["channel"],
                            "resource": enable_result["resource"],
                            "user": enable_result["user"],
                        },
                    ):
                        st.success("Edge updated!")
                    else:
                        st.error("Failed to update edge.")

            # Show record count
            st.caption(
                f"Showing {len(edited_df)} of {len(st.session_state.df_permissions)} permissions"
            )
