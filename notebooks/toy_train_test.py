
import sys
sys.path.append("/home/kalic/Desktop/AI_P/CyberBattleSim")
import logging
import gym
import pickle
import cyberbattle.agents.baseline.learner as learner
import cyberbattle.agents.baseline.plotting as p
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.agent_randomcredlookup as rca
import cyberbattle.agents.baseline.agent_tabularqlearning as tqa
import cyberbattle.agents.baseline.agent_dql as dqla
from cyberbattle.agents.baseline.agent_wrapper import Verbosity

logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")

# Papermill notebook parameters

#############
# gymid = 'CyberBattleTiny-v0'
#############
gymid = "CyberBattleToyCtf-v0"
env_size = None
iteration_count = 20000
training_episode_count = 500
eval_episode_count = 10
maximum_node_count = 12
maximum_total_credentials = 10

#############
# gymid = "CyberBattleChain-v0"
# env_size = 10
# iteration_count = 9000
# training_episode_count = 50
# eval_episode_count = 5
# maximum_node_count = 22
# maximum_total_credentials = 22

# Load the Gym environment
if env_size:
    gym_env = gym.make(gymid, size=env_size)
else:
    gym_env = gym.make(gymid)

ep = w.EnvironmentBounds.of_identifiers(
    maximum_node_count=maximum_node_count,
    maximum_total_credentials=maximum_total_credentials,
    identifiers=gym_env.identifiers
)

debugging = False
if debugging:
    print(f"port_count = {ep.port_count}, property_count = {ep.property_count}")

    gym_env.environment
    # training_env.environment.plot_environment_graph()
    gym_env.environment.network.nodes
    gym_env.action_space
    gym_env.action_space.sample()
    gym_env.observation_space.sample()
    o0 = gym_env.reset()
    o_test, r, d, i = gym_env.step(gym_env.sample_valid_action())
    o0 = gym_env.reset()

    o0.keys()

    fe_example = w.RavelEncoding(ep, [w.Feature_active_node_properties(ep), w.Feature_discovered_node_count(ep)])
    a = w.StateAugmentation(o0)
    w.Feature_discovered_ports(ep).get(a, None)
    fe_example.encode_at(a, 0)


# Evaluate the random agent
random_run = learner.epsilon_greedy_search(
    gym_env,
    ep,
    learner=learner.RandomPolicy(),
    episode_count=eval_episode_count,
    iteration_count=iteration_count,
    epsilon=1.0,  # purely random
    render=False,
    verbosity=Verbosity.Quiet,
    plot_episodes_length=False,
    title="Random search"
)


# Evaluate a random agent that opportunistically exploits
# credentials gathere in its local cache
credlookup_run = learner.epsilon_greedy_search(
    gym_env,
    ep,
    learner=rca.CredentialCacheExploiter(),
    episode_count=training_episode_count,
    iteration_count=iteration_count,
    epsilon=0.90,
    render=False,
    epsilon_exponential_decay=10000,
    epsilon_minimum=0.10,
    verbosity=Verbosity.Quiet,
    title="Credential lookups (ϵ-greedy)"
)

# Evaluate a Tabular Q-learning agent
tabularq_run = learner.epsilon_greedy_search(
    gym_env,
    ep,
    learner=tqa.QTabularLearner(
        ep,
        gamma=0.015, learning_rate=0.01, exploit_percentile=100),
    episode_count=training_episode_count,
    iteration_count=iteration_count,
    epsilon=0.90,
    epsilon_exponential_decay=5000,
    epsilon_minimum=0.01,
    verbosity=Verbosity.Quiet,
    render=False,
    plot_episodes_length=False,
    title="Tabular Q-learning"
)


# Evaluate an agent that exploits the Q-table learnt above
tabularq_exploit_run = learner.epsilon_greedy_search(
    gym_env,
    ep,
    learner=tqa.QTabularLearner(
        ep,
        trained=tabularq_run['learner'],
        gamma=0.0,
        learning_rate=0.0,
        exploit_percentile=90),
    episode_count=eval_episode_count,
    iteration_count=iteration_count,
    epsilon=0.0,
    render=False,
    verbosity=Verbosity.Quiet,
    title="Exploiting Q-matrix"
)

# Evaluate the Deep Q-learning agent
dql_run = learner.epsilon_greedy_search(
    cyberbattle_gym_env=gym_env,
    environment_properties=ep,
    learner=dqla.DeepQLearnerPolicy(
        ep=ep,
        gamma=0.015,
        replay_memory_size=10000,
        target_update=10,
        batch_size=512,
        # torch default learning rate is 1e-2
        # a large value helps converge in less episodes
        learning_rate=0.01
    ),
    episode_count=training_episode_count,
    iteration_count=iteration_count,
    epsilon=0.90,
    epsilon_exponential_decay=5000,
    epsilon_minimum=0.10,
    verbosity=Verbosity.Quiet,
    render=False,
    plot_episodes_length=False,
    title="DQL"
)


with open('./Toy_results/toy_random_run.pkl','wb') as file:
    pickle.dump(random_run, file)
with open('./Toy_results/toy_credlookup_run.pkl','wb') as file:
    pickle.dump(credlookup_run, file)
with open('./Toy_results/toy_tabularq_run.pkl','wb') as file:
    pickle.dump(tabularq_run, file)
with open('./Toy_results/toy_tabularq_exploit_run.pkl','wb') as file:
    pickle.dump(tabularq_exploit_run, file)
with open('./Toy_results/toy_dql_run.pkl','wb') as file:
    pickle.dump(dql_run, file)




gymid = "multoycft_env-v0"
# size_N, size_NGN, dis_type, network_cc, connect_percent
my_gym_env = gym.make(gymid, size_N = 10, size_NGN = 2, dis_type = "gradient_up", network_cc = "chained", connect_percent = 0.5)
my_dql_run = learner.epsilon_greedy_search(
        cyberbattle_gym_env=my_gym_env,
        environment_properties=ep,
        learner=dqla.DeepQLearnerPolicy(
        ep=ep,
        gamma=0.015,
        replay_memory_size=10000,
        target_update=10,
        batch_size=512,
        # torch default learning rate is 1e-2
        # a large value helps converge in less episodes
        learning_rate=0.01
    ),
        episode_count=training_episode_count,
        iteration_count=iteration_count,
        epsilon=0.90,
        epsilon_exponential_decay=5000,
        epsilon_minimum=0.10,
        verbosity=Verbosity.Quiet,
        render=False,
        plot_episodes_length=False,
        title="NVGIL-DQL"
    )

N = 100
for i in range(1, N+1):
    # Evaluate the Deep Q-learning agent
    gymid = "multoycft_env-v0"
    my_gym_env = gym.make(gymid, size_N = 10, size_NGN = 2, dis_type = "gradient_up", network_cc = "chained", connect_percent = 0.5)
    my_dql_run = learner.epsilon_greedy_search(
        cyberbattle_gym_env=my_gym_env,
        environment_properties=ep,
        learner=my_dql_run['learner'],
        episode_count=training_episode_count,
        iteration_count=iteration_count,
        epsilon=0.90,
        epsilon_exponential_decay=5000,
        epsilon_minimum=0.10,
        verbosity=Verbosity.Quiet,
        render=False,
        plot_episodes_length=False,
        title="NVGIL-DQL"
    )
   
    if i % 10 == 0:
        mq_dql_test = my_dql_run
        my_dql_test_run = learner.epsilon_greedy_search(
            cyberbattle_gym_env=gym_env,
            environment_properties=ep,
            learner=mq_dql_test['learner'],
            episode_count=training_episode_count,
            iteration_count=iteration_count,
            epsilon=0.90,
            epsilon_exponential_decay=5000,
            epsilon_minimum=0.10,
            verbosity=Verbosity.Quiet,
            render=False,
            plot_episodes_length=False,
            title="NVGIL-DQL"
        ) 
        filenamei = 'my_dql_test_run_' + str(i) + '.pkl'
        with open(filenamei,'wb') as file:
            pickle.dump(my_dql_test_run, file)
    
