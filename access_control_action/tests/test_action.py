"""Tests for AccessControlAction."""

import os


class TestAccessControlAction:
    """Tests for AccessControlAction."""

    def test_access_control_action(self) -> None:
        """Test AccessControlAction."""

        from jaclang import jac_import
        from jaclang.runtimelib.context import ExecutionContext

        os.environ["JACPATH"] = "./"

        # load the JAC application
        jctx = ExecutionContext.create()

        filename = os.path.join(
            os.path.dirname(__file__),
            "..",
            "access_control_action.jac",
        )

        base, mod = os.path.split(filename)
        base = base if base else "./"
        mod = mod[:-4]

        jac_import(
            target=mod,
            base_path=base,
            cachable=True,
            override_name="__main__",
        )

        jctx.close()

        del os.environ["JACPATH"]
