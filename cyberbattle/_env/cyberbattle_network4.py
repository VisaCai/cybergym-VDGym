# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""CyberBattle environment based on a topology  network structure"""
from ..samples.topology_nodeinfo import networks4_train_test
from . import cyberbattle_env


class CyberBattlenetwork4(cyberbattle_env.CyberBattleEnv):
    """CyberBattle environment based on a toy_ctf  network structure"""

    def __init__(self, state, os_type, Local_vulnerabilities, Remote_vulnerabilities, node_values, topology_graph,installnode,**kwargs):
        self.state = state
        self.os_type = os_type
        self.Local_vulnerabilities = Local_vulnerabilities
        self.Remote_vulnerabilities = Remote_vulnerabilities
        self.node_values = node_values
        self.topology_graph = topology_graph
        self.installnode = installnode
        super().__init__(
            initial_environment=networks4_train_test.generate_specific_network(state, os_type, Local_vulnerabilities, Remote_vulnerabilities, node_values, topology_graph,installnode),
           **kwargs)

    # @ property
    # def name(self) -> str:
    #     return f"topology_and_nodeinfo_env"