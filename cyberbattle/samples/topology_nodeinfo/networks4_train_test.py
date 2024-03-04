from typing import List, Dict, Set
import random
import re
import networkx as nx
import numpy as np
import sys
sys.path.append("/home/kalic/Desktop/AI_P/CyberBattleSim")
from cyberbattle.simulation import model
from cyberbattle.simulation.model import Identifiers, NodeID, CredentialID, PortName, FirewallConfiguration, FirewallRule, RulePermission
import itertools as itts
import collections as col

ADMINTAG = model.AdminEscalation().tag
SYSTEMTAG = model.SystemEscalation().tag

potential_windows_vulns_local = {
    "MS16-111":
    model.VulnerabilityInfo(
        description= "SMB",
        type=model.VulnerabilityType.LOCAL,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0.8, 0.8, 1.0)),  
    "CVE-2009-0079":
    model.VulnerabilityInfo(
        description= "RDP",
        type=model.VulnerabilityType.LOCAL,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node="",
                                       port="RDP",
                                       credential="RDPCreds")]),
        rates=model.Rates(0.8, 0.8, 1.0),
        cost=1.0),  
    "MS15-015":
    model.VulnerabilityInfo(
        description= "E-cology 9.0",
        type=model.VulnerabilityType.LOCAL,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0.8, 0.8, 1.0)),
    "CVE-2009-0708":
    model.VulnerabilityInfo(
        description= "E-cology 9.0",
        type=model.VulnerabilityType.LOCAL,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node="",
                                       port="SSH",
                                       credential="SSHCreds")]),
        rates=model.Rates(0.8, 0.8, 1.0)),
}
potential_windows_vulns_remote = {
    "S2-048":
    model.VulnerabilityInfo(
        description= "",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        outcome=model.LateralMove(),
        rates=model.Rates(0.8, 0.8, 1.0)),
    "CNVD-2019-32204":
    model.VulnerabilityInfo(
        description= "E-cology 9.0",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LateralMove(),
        rates=model.Rates(0.8, 0.8, 1.0)),   
    "MS17-010":
    model.VulnerabilityInfo(
        description= "SMB",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LateralMove(),
        rates=model.Rates(0.8, 0.8, 1.0)),     
    "MS08-067":
    model.VulnerabilityInfo(
        description= "SMB",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LateralMove(),
        rates=model.Rates(0.8, 0.8, 1.0)),  
    "CVE-2019-0708":
    model.VulnerabilityInfo(
        description= "SSH, RDP",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LeakedCredentials(credentials=[
            model.CachedCredential(node="",
                                port="SSH",
                                credential="SSHCreds")]),
        rates=model.Rates(0.8, 0.8, 1.0)),  
    "MS09-050":
    model.VulnerabilityInfo(
        description= "SMB",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LateralMove(),
        rates=model.Rates(0.8, 0.8, 1.0))  

}
potential_linux_vulns_local = {

}
potential_linux_vulns_remote = {

}
potential_ubuntu_vulns_local = {
    "CVE-2017-16995":
    model.VulnerabilityInfo(
        description= "wEBLOGIC 12.3.1, HTTP, HTTPS, SSH, RDP, SMB",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2017-16995",
        outcome=model.AdminEscalation(),
        rates=model.Rates(0.8, 0.8, 1.0)),
    "CVE-2022-0847":
    model.VulnerabilityInfo(
        description= "",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2017-16995",
        outcome=model.AdminEscalation(),
        rates=model.Rates(0.8, 0.8, 1.0)),
}
potential_ubuntu_vulns_remote = {
    "CVE-2019-2729":
    model.VulnerabilityInfo(
        description= "MySql, SSH",
        type=model.VulnerabilityType.REMOTE,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2019-2729",
        outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node="",
                                       port="SSH",
                                       credential="Mysql-Conf-file")]),
        rates=model.Rates(0.8, 0.8, 1.0),
        cost=1.0),
    "S2-048":
    model.VulnerabilityInfo(
        description= "",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LateralMove(),
        rates=model.Rates(0.8, 0.8, 1.0)),
}

potential_scan = {
    "Scan":
    model.VulnerabilityInfo(
        description="Scan to find node",
        type=model.VulnerabilityType.LOCAL,
        URL="",
        # precondition=model.Precondition(f""),
        outcome=model.LeakedNodesId([]),
        rates=model.Rates(0.8, 0.8, 1.0)),
    "Search":
    model.VulnerabilityInfo(
        description="Search informations, SSH",
        type=model.VulnerabilityType.LOCAL,
        URL="",
        outcome=model.LeakedCredentials(credentials=[
            model.CachedCredential(node="",
                                port="SSH",
                                credential="Mysql-Conf-file")]),
        rates=model.Rates(0.8, 0.8, 1.0)),   
}

# These are potential endpoints that can be open in a game. Note to add any more endpoints simply
# add the protocol name to this list.
# further note that ports are stored in a tuple. This is because some protoocls
# (like SMB) have multiple official ports.
potential_ports: List[model.PortName] = ["RDP", "SSH", "HTTP", "HTTPs",
                                         "SMB", "SQL", "FTP", "WMI"]

# These two lists are potential node states. They are split into linux states and windows
#  states so that we can generate real graphs that aren't just totally random.
potential_linux_node_states: List[model.PropertyName] = ["Linux", ADMINTAG,
                                                         "PortRDPOpen",
                                                         "PortHTTPOpen", "PortHTTPsOpen",
                                                         "PortSSHOpen", "PortSMBOpen",
                                                         "PortFTPOpen", "DomainJoined"]
potential_windows_node_states: List[model.PropertyName] = ["Windows", "Win10", "PortRDPOpen",
                                                           "PortHTTPOpen", "PortHTTPsOpen",
                                                           "PortSSHOpen", "PortSMBOpen",
                                                           "PortFTPOpen", "BITSEnabled",
                                                           "Win7", "DomainJoined"]
potential_ubuntu_node_states: List[model.PropertyName] = ["PortRDPOpen","Ubuntu"
                                                           "PortHTTPOpen", "PortHTTPsOpen",
                                                           "PortSSHOpen", "PortSMBOpen",
                                                           "PortFTPOpen", "BITSEnabled",
                                                           "DomainJoined"]
ENV_IDENTIFIERS = model.Identifiers(
    ports=potential_ports,
    properties=potential_linux_node_states + potential_windows_node_states + potential_ubuntu_node_states,
    local_vulnerabilities=list(potential_windows_vulns_local.keys()) + \
        list(potential_linux_vulns_local.keys()) + list(potential_ubuntu_vulns_local.keys()) + list(potential_scan.keys()),
    remote_vulnerabilities=list(potential_windows_vulns_remote.keys()) + \
    list(potential_linux_vulns_remote.keys()) + list(potential_ubuntu_vulns_remote.keys()) 
)


def get_service_from_vulnerabilities(end_points:List[model.PortName], vulns: Dict[model.NodeID, model.VulnerabilityInfo]) \
        -> List[model.PortName]:
    """
        get_properties_from_vulnerabilities function.
        This function takes a string for os_type and returns a list of PortName objects
    """
    ret_val: Set[model.PortName] = set()

    for service_i in end_points:
        for vuln_id, vuln in vulns.items():
            if re.search(service_i, str(vuln.description)):
                ret_val.add(service_i)

    return list(ret_val)

def get_properties_from_vulnerabilities(os_type: str,
                                        vulns: Dict[model.NodeID, model.VulnerabilityInfo]) \
        -> List[model.PropertyName]:
    """
        get_properties_from_vulnerabilities function.
        This function takes a string for os_type and returns a list of PropertyName objects
    """
    ret_val: Set[model.PropertyName] = set()
    properties: List[model.PropertyName] = []

    if os_type == "Linux":
        properties = potential_linux_node_states
    elif os_type == "Windows":
        properties = potential_windows_node_states
    else:
        properties = potential_ubuntu_node_states

    for prop in properties:
        for vuln_id, vuln in vulns.items():
            if re.search(prop, str(vuln.precondition.expression)):
                ret_val.add(prop)

    return list(ret_val)


def create_firewall_rules(end_points: List[model.PortName]) -> model.FirewallConfiguration:
    """
        This function takes a List of endpoints and returns a FirewallConfiguration

        It iterates through the list of potential ports and if they're in the list passed
        to the function it adds a firewall rule allowing that port.
        Otherwise it adds a rule blocking that port.
    """

    ret_val: model.FirewallConfiguration = model.FirewallConfiguration()
    ret_val.incoming.clear()
    ret_val.outgoing.clear()
    for protocol in potential_ports:
        if protocol in end_points:
            ret_val.incoming.append(model.FirewallRule(protocol, model.RulePermission.ALLOW))
            ret_val.outgoing.append(model.FirewallRule(protocol, model.RulePermission.ALLOW))
        else:
            ret_val.incoming.append(model.FirewallRule(protocol, model.RulePermission.BLOCK))
            ret_val.outgoing.append(model.FirewallRule(protocol, model.RulePermission.BLOCK))

    return ret_val



# creat distubution list
def topology_list_with_dis_type(size_N: int, size_NGN: int, dis_type: str)->List:
    """
    size_N: Number of Hosts
    size_NGN( < size_N): Network Group Number
    dis_type: Distribution: random, uniform, gradient_up, gradient_down
    """
    if size_N < 1 or size_NGN > size_N:
        raise ValueError("Please supply a positive non zero positive of size_N, and size_NGN( < size_N)")
    
    size_NGN_dis_type = [0] * size_NGN
    dis_average, dis_mod = divmod(size_N, size_NGN)
    if dis_type == "random":
        left_size = size_N
        for i in range(size_NGN-1):
            size_NGN_dis_type[i] = random.randrange(left_size)
            left_size -= size_NGN_dis_type[i]
        size_NGN_dis_type[-1] = left_size
    elif dis_type == "uniform":
        for i in range(size_NGN):
            size_NGN_dis_type[i] = dis_average + (dis_mod >= 1)
            dis_mod -= 1
    elif dis_type == "gradient_up":
        mid_index = (size_NGN - 1) // 2
        size_NGN_dis_type[mid_index] = dis_average
        for i in range(mid_index+1, size_NGN):
            size_NGN_dis_type[i] = size_NGN_dis_type[i-1] + 1 if (dis_mod > 1) else size_NGN_dis_type[i-1]
            dis_mod -= 1
        for i in range(mid_index-1, -1, -1):
            size_NGN_dis_type[i] = size_NGN_dis_type[i+1] - 1 + (dis_mod >= 1)
            dis_mod -= 1
    elif  dis_type == "gradient_down":
        mid_index = (size_NGN - 1) // 2
        size_NGN_dis_type[mid_index] = dis_average
        for i in range(mid_index+1, size_NGN):
            size_NGN_dis_type[i] = size_NGN_dis_type[i-1] - 1 + (dis_mod >= 1)
            dis_mod -= 1

        for i in range(mid_index-1, -1, -1):
            size_NGN_dis_type[i] = size_NGN_dis_type[i+1] + 1 + (dis_mod >= 1)
            dis_mod -= 1       
    else:
        raise ValueError("Please input a valueable dis_type")
    return size_NGN_dis_type

# creat topology
def edges_relation_with_network_cc(size_NGN_dis_type_list:list, size_NGN: int, network_cc: str, connect_percent: float):
    """network_cc: Connectivity Configurations: chained, hub-spoke, random"""
    network_edges = col.defaultdict(list)

    # edges in one group
    sumpre = list(itts.accumulate(size_NGN_dis_type_list, initial = 0))
    for i in range(size_NGN):
        for e1, e2 in list(itts.combinations(list(range(size_NGN_dis_type_list[i])), 2)):
            network_edges[str(sumpre[i]+e1)].append(str(sumpre[i]+e2))  
            network_edges[str(sumpre[i]+e2)].append(str(sumpre[i]+e1))  

    
    # edges between two groups
    if network_cc == "chained":
        for i in range(size_NGN - 1):
            sample_num_1 = np.clip(int(size_NGN_dis_type_list[i] * connect_percent), a_min=1, a_max=size_NGN_dis_type_list[i])
            sample_num_2 = np.clip(int(size_NGN_dis_type_list[i+1] * connect_percent), a_min=1, a_max=size_NGN_dis_type_list[i+1])
            group1 = random.sample(list(range(size_NGN_dis_type_list[i])), sample_num_1)
            group2 = random.sample(list(range(size_NGN_dis_type_list[i+1])), sample_num_2)
            for e1, e2 in itts.product(group1, group2):
                network_edges[str(sumpre[i]+e1)].append(str(sumpre[i+1]+e2))  
                network_edges[str(sumpre[i+1]+e2)].append(str(sumpre[i]+e1))  

    elif network_cc == "hub-spoke":
        mid_colect_index = size_NGN // 2
        sample_num_1 = np.clip(int(size_NGN_dis_type_list[mid_colect_index] * connect_percent), a_min=1, a_max=size_NGN_dis_type_list[mid_colect_index])
        for i in range(size_NGN): 
            if i != mid_colect_index:            
                sample_num_2 = np.clip(int(size_NGN_dis_type_list[i] * connect_percent), a_min=1, a_max=size_NGN_dis_type_list[i])
                group1 = random.sample(list(range(size_NGN_dis_type_list[mid_colect_index])), sample_num_1)
                group2 = random.sample(list(range(size_NGN_dis_type_list[i])), sample_num_2)
                for e1, e2 in itts.product(group1, group2):
                    network_edges[str(sumpre[mid_colect_index]+e1)].append(str(sumpre[i]+e2)) 
                    network_edges[str(sumpre[i]+e2)].append(str(sumpre[mid_colect_index]+e1)) 
    elif network_cc == "random":
        for g1, g2 in random.sample(list(itts.combinations(list(range(size_NGN)), 2)), size_NGN): 
            sample_num_1 = np.clip(int(size_NGN_dis_type_list[g1] * connect_percent), a_min=1, a_max=size_NGN_dis_type_list[g1])
            sample_num_2 = np.clip(int(size_NGN_dis_type_list[g2] * connect_percent), a_min=1, a_max=size_NGN_dis_type_list[g2])
            group1 = random.sample(list(range(size_NGN_dis_type_list[g1])), sample_num_1)
            group2 = random.sample(list(range(size_NGN_dis_type_list[g2])), sample_num_2)
            for e1, e2 in itts.product(group1, group2):
                network_edges[str(sumpre[g1]+e1)].append(str(sumpre[g2]+e2))    
                network_edges[str(sumpre[g2]+e2)].append(str(sumpre[g1]+e1)) 
    else:
        raise ValueError("Please input a valuable network_cc")


    return network_edges

# return topology_graph
def creat_topology_of_a_network(size_N: int, size_NGN: int, dis_type: str, network_cc: str, connect_percent: float)-> nx.DiGraph: 
    """
    size_N: Number of Hosts
    size_NGN( < size_N): Network Group Number
    dis_type: Distribution: random, uniform, gradient_up, gradient_down
    network_cc: Connectivity Configurations: chained, hub-spoke, random
    connect_percent: Connectivity Percent
    """
    size_NGN_dis_type_list = topology_list_with_dis_type(size_N, size_NGN, dis_type)    
    
    # set backed multidict
    network_edges = edges_relation_with_network_cc(size_NGN_dis_type_list, size_NGN, network_cc, connect_percent)    

    return network_edges


def select_random_vulnerabilities_keys(size_N: int, os_type: list()):
    """
        Local and remote keys for each node 
    """
    local_keys = []
    remote_keys = []
    for i in range(size_N):
        os_typei = os_type[i]
        if os_typei == "Linux":
            local_num = random.randint(1, len(potential_linux_vulns_local))
            remote_num = random.randint(1, len(potential_linux_vulns_remote))
            local_keys.append(random.sample(list(potential_linux_vulns_local.keys()), local_num))
            remote_keys.append(random.sample(list(potential_linux_vulns_remote.keys()), remote_num))
        elif os_typei == "Windows":
            local_num = random.randint(1, len(potential_windows_vulns_local))
            remote_num = random.randint(1, len(potential_windows_vulns_remote))
            local_keys.append(random.sample(list(potential_windows_vulns_local.keys()), local_num))
            remote_keys.append(random.sample(list(potential_windows_vulns_remote.keys()), remote_num))
        elif os_typei == "Ubuntu":
            local_num = random.randint(1, len(potential_ubuntu_vulns_local))
            remote_num = random.randint(1, len(potential_ubuntu_vulns_remote))
            local_keys.append(random.sample(list(potential_ubuntu_vulns_local.keys()), local_num))
            remote_keys.append(random.sample(list(potential_ubuntu_vulns_remote.keys()), remote_num))
        else:
            raise ValueError("Invalid Operating System supplied to select_random_vulnerabilities_keys")
    return local_keys, remote_keys


def select_specific_vulnerabilities(os_type: str, local_vul: list, remote_vul: list) \
        -> Dict[str, model.VulnerabilityInfo]:
    """
        It takes an a string for the OS type,  and lists for the number of
        vulnerabilities to select. It returns a dictionary of VulnerabilityInfo objects to
        the caller.
    """

    ret_val: Dict[str, model.VulnerabilityInfo] = {}
    keys: List[str]

    keys = local_vul + remote_vul
    if "Search" in keys:
        ret_val["Search"] = potential_scan["Search"]
        keys.remove("Search")
    if os_type == "Linux":
        ret_val = {k: potential_linux_vulns_local[k] if k in potential_linux_vulns_local else potential_linux_vulns_remote[k] for k in keys} 
    elif os_type == "Windows":
        ret_val = {k: potential_windows_vulns_local[k] if k in potential_windows_vulns_local else potential_windows_vulns_remote[k] for k in keys} 
    elif os_type == "Ubuntu":
        ret_val = {k: potential_ubuntu_vulns_local[k] if k in potential_ubuntu_vulns_local else potential_ubuntu_vulns_remote[k] for k in keys} 
    else:
        raise ValueError("Invalid Operating System supplied to select_random_vulnerabilities")

    return ret_val

def create_random_node_info(os_type: str, local_vuls: list, remote_vuls:list, end_points, node_value:int) \
        -> model.NodeInfo:
    """
        This is the create random node function.
        Currently it takes a string for the OS type and returns a NodeInfo object
        Options for OS type are currently Linux, Windows or Ubuntu,
        Options for the role are Server or Workstation
    """

    if os_type not in ("Windows", "Linux", "Ubuntu"):
        raise ValueError("Unsupported OS Type please enter Linux, Windows, Ubuntu")

    # get the vulnerability dictionary for the important OS
    vulnerabilities: model.VulnerabilityLibrary = dict([])
    vulnerabilities = select_specific_vulnerabilities(os_type, local_vuls, remote_vuls)
    
    service_for_the_node = get_service_from_vulnerabilities(end_points, vulnerabilities)
    if len(service_for_the_node) == 0:
        firewall: model.FirewallConfiguration = create_firewall_rules(["SSH"])
    else:
        firewall: model.FirewallConfiguration = create_firewall_rules(service_for_the_node)
    properties: List[model.PropertyName] = \
        get_properties_from_vulnerabilities(os_type, vulnerabilities)
    return model.NodeInfo(services=[model.ListeningService(name=p) for p in service_for_the_node],
                          vulnerabilities=vulnerabilities,
                          value=node_value,
                          properties=properties,
                          firewall=firewall,
                          agent_installed=False)

def generate_node_with_info(os_type:list, Local_vulnerabilities:list, Remote_vulnerabilities:list, node_values:list):

    nodes: Dict[str, model.NodeInfo] = {}

    for i in range(len(os_type)):
        nodes[str(i)] = create_random_node_info(os_type[i], Local_vulnerabilities[i], Remote_vulnerabilities[i], potential_ports, node_values[i])

    return nodes



def combine_node_info_with_topology_graph(size_N, nodes_info: Dict[str, model.NodeInfo], topology_graph: Dict[int, list],installnode)->nx.DiGraph:
    graph = nx.DiGraph() 
    graph.add_nodes_from([(k, {'data': v}) for (k, v) in list(nodes_info.items())])

    for node1 in graph.nodes:
        

        if node1 in topology_graph:
            # print(node1, node2, isinstance(node1, str), (node1, node2) in topology_graph)
            for nextnode in topology_graph[node1]:
                graph.nodes[node1]["data"].vulnerabilities["Scan"] =  model.VulnerabilityInfo(
                description="scan and find a node",
                type=model.VulnerabilityType.LOCAL,
                outcome=model.LeakedNodesId([nextnode]),
                reward_string="new node discovered!",
                cost=1.0)
            if "Search" in graph.nodes[node1]["data"].vulnerabilities:
                graph.nodes[node1]["data"].vulnerabilities["Search"] =  model.VulnerabilityInfo(
                description="scan and find a crediental",
                type=model.VulnerabilityType.LOCAL,
                outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node=topology_graph[node1][0],
                                port="SSH",
                                credential="Mysql-Conf-file")]),
                reward_string="new node discovered!",
                cost=1.0)   
                graph.nodes[topology_graph[node1][0]]["data"].services.append(model.ListeningService("SSH",allowedCredentials=['Mysql-Conf-file'])) 


        for vul in graph.nodes[node1]["data"].vulnerabilities:
            if isinstance(graph.nodes[node1]["data"].vulnerabilities[vul].outcome, model.LeakedNodesId):
                typei = graph.nodes[node1]["data"].vulnerabilities[vul].type
                graph.nodes[node1]["data"].vulnerabilities[vul] = model.VulnerabilityInfo(
                    description="Search web history for list of accessed websites",
                    type=typei,
                    outcome=model.LeakedNodesId(topology_graph[node1]),
                    reward_string="Web browser history revealed website URL of interest",
                    cost=1.0)
            elif isinstance(graph.nodes[node1]["data"].vulnerabilities[vul].outcome, model.LeakedCredentials):
                if node1 in topology_graph:
                    nextnode = random.choice(topology_graph[node1])
                    while nextnode == "0":
                        nextnode = random.choice(topology_graph[node1])
                else:
                    nextnode = random.choice([str(ij) for ij in range(int(node1), size_N)])
                descriptioni = graph.nodes[node1]["data"].vulnerabilities[vul].description
                typei = graph.nodes[node1]["data"].vulnerabilities[vul].type
                nextnode_info = graph.nodes[node1]["data"].vulnerabilities[vul].outcome.credentials[0]
                rewardi = graph.nodes[node1]["data"].vulnerabilities[vul].reward_string

                graph.nodes[node1]["data"].vulnerabilities[vul] = model.VulnerabilityInfo(
                    description=descriptioni,
                    type=typei,
                    outcome=model.LeakedCredentials(credentials=[
                        model.CachedCredential(node=nextnode, port=nextnode_info.port, credential=nextnode_info.credential)
                    ]),
                    reward_string=rewardi,
                    cost=1.0) 
                graph.nodes[nextnode]["data"].services.append(model.ListeningService(nextnode_info.port, allowedCredentials=[
                        nextnode_info.credential])) 
            else:
                pass
    if installnode:
        for nodeid in installnode:
            graph.nodes[str(nodeid)]["data"].agent_installed = True
    graph.nodes[str(0)]["data"].agent_installed = True
    return graph


def generate_specific_network(state:str, os_type:list, Local_vulnerabilities:list, Remote_vulnerabilities:list, node_values:list, topology_graph: set,installnode:list):
    """Create a new simulation environment based on a designed generated network topology.

    NOTE: the probabilities and parameter values used
    here for the statistical generative model
    were arbirarily picked. We recommend exploring different values for those parameters.
    """
    Vul_L = len(ENV_IDENTIFIERS.local_vulnerabilities) + len(ENV_IDENTIFIERS.remote_vulnerabilities)
    size_N = random.randint(Vul_L//2, 10) if not os_type else len(os_type)
    os_type_for_choose: List[str] = ["Windows", "Ubuntu", "Linux"]
    if state == "random":
        os_type = [os_type_for_choose[random.randint(0,1)] for _ in range(size_N)]
        Local_vulnerabilities, Remote_vulnerabilities = select_random_vulnerabilities_keys(size_N, os_type)
        # node_values = np.random.shuffle(node_values)
        node_values = random.sample(node_values, size_N)
        topology_graph = creat_topology_of_a_network(size_N, 2, "gradient_up", "chained", 0.5)
        
    node_graph = generate_node_with_info(os_type, Local_vulnerabilities, Remote_vulnerabilities, node_values)
    
    graph = combine_node_info_with_topology_graph(size_N, node_graph, topology_graph,installnode)
    # for i in range(size_N):
    #     print(i, graph.nodes[str(i)])
    return model.Environment(network=graph,
                         vulnerability_library=dict([]),
                         identifiers=ENV_IDENTIFIERS)
