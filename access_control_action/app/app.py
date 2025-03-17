"""This module contains the render function for the access control action app."""

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
    app_controls(agent_id, action_id)
    app_update_action(agent_id, action_id)
