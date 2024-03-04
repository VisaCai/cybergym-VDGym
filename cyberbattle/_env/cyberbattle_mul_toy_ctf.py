# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""CyberBattle environment based on a topology  network structure"""

from ..samples.toyctf import mul_toy_ctf
from . import cyberbattle_env


class CyberBattlemultoycft(cyberbattle_env.CyberBattleEnv):
    """CyberBattle environment based on a toy_ctf  network structure"""

    def __init__(self, size_N, size_NGN, dis_type, network_cc, connect_percent,**kwargs):
        self.size_N = size_N
        self.size_NGN = size_NGN
        self.dis_type = dis_type
        self.network_cc = network_cc
        self.connect_percent = connect_percent
        super().__init__(
            initial_environment=mul_toy_ctf.new_environment(size_N, size_NGN, dis_type, network_cc, connect_percent),
           **kwargs)

    # @ property
    # def name(self) -> str:
    #     return f"topology_and_nodeinfo_env"
