# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""CyberBattle environment based on a topology  network structure"""

from ..samples.topology_nodeinfo import one_node_vul
from . import cyberbattle_env


class CyberBattleonenodevul(cyberbattle_env.CyberBattleEnv):
    """CyberBattle environment based on a topology  network structure"""

    def __init__(self, size_N, **kwargs):
        self.size_N = size_N

        super().__init__(
            initial_environment=one_node_vul.new_environment(size_N),
           **kwargs)

    # @ property
    # def name(self) -> str:
    #     return f"topology_and_nodeinfo_env"
