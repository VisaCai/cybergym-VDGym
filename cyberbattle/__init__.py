# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Initialize CyberBattleSim module"""
from gym.envs.registration import registry, EnvSpec
from gym.error import Error
import sys
sys.path.append("/home/kalic/Desktop/AI_P/CyberBattleSim/cyberbattle")
import simulation
import agents
from _env.cyberbattle_env import AttackerGoal, DefenderGoal
from samples.chainpattern import chainpattern
from samples.toyctf import toy_ctf
from samples.active_directory import generate_ad
from samples.topology_nodeinfo import topology_and_nodeinfo_env, networks4_train_test, one_node_vul
from samples.toyctf import mul_toy_ctf
from simulation import generate_network, model
import gym

__all__ = (
    'simulation',
    'agents',
)


def register(id: str, cyberbattle_env_identifiers: model.Identifiers, **kwargs):
    """ same as gym.envs.registry.register, but adds CyberBattle specs to env.spec  """
    if id in registry.env_specs:
        raise Error('Cannot re-register id: {}'.format(id))
    spec = EnvSpec(id, **kwargs)
    # Map from port number to port names : List[model.PortName]
    spec.ports = cyberbattle_env_identifiers.ports
    # Array of all possible node properties (not necessarily all used in the network) : List[model.PropertyName]
    spec.properties = cyberbattle_env_identifiers.properties
    # Array defining an index for every possible local vulnerability name : List[model.VulnerabilityID]
    spec.local_vulnerabilities = cyberbattle_env_identifiers.local_vulnerabilities
    # Array defining an index for every possible remote  vulnerability name : List[model.VulnerabilityID]
    spec.remote_vulnerabilities = cyberbattle_env_identifiers.remote_vulnerabilities

    registry.env_specs[id] = spec


if 'topology_and_nodeinfo_env-v0' in registry.env_specs:
    del registry.env_specs['topology_and_nodeinfo_env-v0']

register(
    id='topology_and_nodeinfo_env-v0',
    cyberbattle_env_identifiers=topology_and_nodeinfo_env.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_topology_and_nodeinfo:CyberBattletopology',
    kwargs={'size_N': 7,
            'size_NGN': 2,
            'dis_type': "gradient_up",
            'network_cc' : "chained",
            'connect_percent' : 0.9
            },
    # max_episode_steps=2600,
)
# gymid = "topology_and_nodeinfo_env-v0"
# print("now")
# gym_env = gym.make(gymid, size_N = 7, size_NGN = 2, dis_type = "gradient_up", network_cc = "chained", connect_percent = 0.9)

if 'network4-v0' in registry.env_specs:
    del registry.env_specs['network4-v0']

register(
    id='network4-v0',
    cyberbattle_env_identifiers=networks4_train_test.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_network4:CyberBattlenetwork4',
    kwargs={'state': "random",
            'os_type': ["Windows", "Ubuntu", "Windows", "Ubuntu", "Windows", "Windows", "Windows", "Windows", "Windows", "Windows"],
            'Local_vulnerabilities': [[], ["CVE-2017-16995"], ["CVE-2009-0079"], ["CVE-2017-16995"], ["MS15-015"], [], [], [], [], []],
            'Remote_vulnerabilities' : [[], ["CVE-2019-2729"], ["S2-048"], [], ["CNVD-2019-32204"], ["MS17-010"], ["MS17-010"], ["MS08-067"], ["CVE-2019-0708"],["MS09-050"]],
            'node_values' : [0, 50, 30, 60, 60, 50, 50, 50, 300, 1000],
            'topology_graph':{"0":["1","2"], "1":["3"],"3":["4","5","6","7","8"], "4":["5","6","7","8"], "5":["6","7","8"], "6":["7", "8"], "7":["8"], "8":["9"]},
            'installnode':[4]
            },
)

if 'onenodevul-v0' in registry.env_specs:
    del registry.env_specs['network4-v0']

register(
    id='onenodevul-v0',
    cyberbattle_env_identifiers=one_node_vul.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_one_node_vul:CyberBattleonenodevul',
    kwargs={'size_N': 2,
            'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast=2),
            'defender_goal': DefenderGoal(eviction=True)
            },
)


if 'multoycft_env-v0' in registry.env_specs:
    del registry.env_specs['multoycft_env-v0']

register(
    id='multoycft_env-v0',
    cyberbattle_env_identifiers=mul_toy_ctf.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_mul_toy_ctf:CyberBattlemultoycft',
    kwargs={'size_N': 10,
            'size_NGN': 2,
            'dis_type': "gradient_up",
            'network_cc' : "chained",
            'connect_percent' : 0.5,
            'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast=6),
            'defender_goal': DefenderGoal(eviction=True)
            },
    # max_episode_steps=2600,
)

if 'CyberBattleToyCtf-v0' in registry.env_specs:
    del registry.env_specs['CyberBattleToyCtf-v0']

register(
    id='CyberBattleToyCtf-v0',
    cyberbattle_env_identifiers=toy_ctf.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_toyctf:CyberBattleToyCtf',
    kwargs={'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast=6),
            'defender_goal': DefenderGoal(eviction=True)
            },
    # max_episode_steps=2600,
)

if 'CyberBattleTiny-v0' in registry.env_specs:
    del registry.env_specs['CyberBattleTiny-v0']

register(
    id='CyberBattleTiny-v0',
    cyberbattle_env_identifiers=toy_ctf.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_tiny:CyberBattleTiny',
    kwargs={'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast=6),
            'defender_goal': DefenderGoal(eviction=True),
            'maximum_total_credentials': 10,
            'maximum_node_count': 10
            },
    # max_episode_steps=2600,
)


if 'CyberBattleRandom-v0' in registry.env_specs:
    del registry.env_specs['CyberBattleRandom-v0']

register(
    id='CyberBattleRandom-v0',
    cyberbattle_env_identifiers=generate_network.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_random:CyberBattleRandom',
)

if 'CyberBattleChain-v0' in registry.env_specs:
    del registry.env_specs['CyberBattleChain-v0']

register(
    id='CyberBattleChain-v0',
    cyberbattle_env_identifiers=chainpattern.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.cyberbattle_chain:CyberBattleChain',
    kwargs={'size': 4,
            'defender_agent': None,
            'attacker_goal': AttackerGoal(own_atleast_percent=1.0),
            'defender_goal': DefenderGoal(eviction=True),
            'winning_reward': 5000.0,
            'losing_reward': 0.0
            },
    reward_threshold=2200,
)

ad_envs = [f"ActiveDirectory-v{i}" for i in range(0, 10)]
for (index, env) in enumerate(ad_envs):
    if env in registry.env_specs:
        del registry.env_specs[env]

    register(
        id=env,
        cyberbattle_env_identifiers=generate_ad.ENV_IDENTIFIERS,
        entry_point='cyberbattle._env.active_directory:CyberBattleActiveDirectory',
        kwargs={
            'seed': index,
            'maximum_discoverable_credentials_per_action': 50000,
            'maximum_node_count': 30,
            'maximum_total_credentials': 50000,
        }
    )

if 'ActiveDirectoryTiny-v0' in registry.env_specs:
    del registry.env_specs['ActiveDirectoryTiny-v0']
register(
    id='ActiveDirectoryTiny-v0',
    cyberbattle_env_identifiers=chainpattern.ENV_IDENTIFIERS,
    entry_point='cyberbattle._env.active_directory:CyberBattleActiveDirectoryTiny',
    kwargs={'maximum_discoverable_credentials_per_action': 50000,
            'maximum_node_count': 30,
            'maximum_total_credentials': 50000
            }
)

# gymid = "CyberBattleChain-v0"
# env_size = 10
# gym_env = gym.make(gymid, size=env_size)


# print(gym.envs.registry.all())
