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

}
potential_windows_vulns_remote = {

}

potential_linux_vulns_remote = {
    
}

potential_linux_vulns_local = {

    
}

potential_Ubuntu_vulns_local = {
   
}

potential_ubuntu_vulns_remote = {

}

potential_scan = {
    "Scan":
    model.VulnerabilityInfo(
        description="Scan to find node",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        precondition=model.Precondition(f"win7|win8|win10|Linux"),
        outcome=model.LeakedCredentials([]),
        rates=model.Rates(0, 0.2, 1.0))
}
potential_service_vulns = {
    "CVE-2021-25646":
    model.VulnerabilityInfo(
        description="Apache Druid",
        type=model.VulnerabilityType.REMOTE,
        URL="https://nvd.nist.gov/vuln/detail/cve-2021-25646",
        precondition=model.Precondition(f"(Ubuntu|Linux)&Apache"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 0.2, 1.0))
}

# These are potential endpoints that can be open in a game. Note to add any more endpoints simply
# add the protocol name to this list.
# further note that ports are stored in a tuple. This is because some protoocls
# (like SMB) have multiple official ports.
potential_ports: List[model.PortName] = [str(i) for i in range(90,100)]
# potential_ports: List[model.PortName] = ["RDP", "SSH", "HTTP", "HTTPs", "SMB", "SQL", "FTP", "WMI"]

# These two lists are potential node states. They are split into linux states and windows
#  states so that we can generate real graphs that aren't just totally random.
# potential_linux_node_states: List[model.PropertyName] = ["Linux", ADMINTAG,
#                                                          "PortRDPOpen",
#                                                          "PortHTTPOpen", "PortHTTPsOpen",
#                                                          "PortSSHOpen", "PortSMBOpen",
#                                                          "PortFTPOpen", "DomainJoined"]
# potential_windows_node_states: List[model.PropertyName] = ["Windows", "Win10", "PortRDPOpen",
#                                                            "PortHTTPOpen", "PortHTTPsOpen",
#                                                            "PortSSHOpen", "PortSMBOpen",
#                                                            "PortFTPOpen", "BITSEnabled",
#                                                            "Win7", "DomainJoined"]
# potential_ubuntu_node_states: List[model.PropertyName] = ["PortRDPOpen","Ubuntu"
#                                                            "PortHTTPOpen", "PortHTTPsOpen",
#                                                            "PortSSHOpen", "PortSMBOpen",
#                                                            "PortFTPOpen", "BITSEnabled",
#                                                            "DomainJoined"]

ENV_IDENTIFIERS = model.Identifiers(
    ports=potential_ports,
    # properties=potential_linux_node_states + potential_windows_node_states,
    properties= potential_ports, 
    local_vulnerabilities=list(potential_windows_vulns_local.keys()) + \
        list(potential_linux_vulns_local.keys()) + list(potential_Ubuntu_vulns_local.keys()) + list(potential_scan.keys()),
    remote_vulnerabilities=list(potential_windows_vulns_remote.keys()) + \
    list(potential_linux_vulns_remote.keys()) + list(potential_ubuntu_vulns_remote.keys()) + list(potential_service_vulns.keys())
)

# print(ENV_IDENTIFIERS)


def get_properties_from_vulnerabilities(os_type: str,
                                        vulns: Dict[model.NodeID, model.VulnerabilityInfo], service_for_the_node) \
        -> List[model.PropertyName]:
    """
        get_properties_from_vulnerabilities function.
        This function takes a string for os_type and returns a list of PropertyName objects
    """
    ret_val: Set[model.PropertyName] = set()
    properties: List[model.PropertyName] = service_for_the_node

    # if os_type == "Linux":
    #     properties = potential_linux_node_states
    # elif os_type == "Windows":
    #     properties = potential_windows_node_states
    # else:
    #     properties = potential_ubuntu_node_states

    for prop in properties:
        for vuln_id, vuln in vulns.items():
            if re.search(prop, str(vuln.precondition.expression)):
                ret_val.add(prop)

    return list(ret_val)

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

def create_random_node_info(os_type: str, end_points: List[model.PortName], vulnerabilities, serviceid) \
        -> model.NodeInfo:
    """
        This is the create random node function.
        Currently it takes a string for the OS type and returns a NodeInfo object
        Options for OS type are currently Linux, Windows or Ubuntu,
        Options for the role are Server or Workstation
    """
    if not end_points:
        raise ValueError("No endpoints supplied")

    if os_type not in ("Windows", "Linux", "Ubuntu"):
        raise ValueError("Unsupported OS Type please enter Linux, Windows, Ubuntu")

    # service_for_the_node = get_service_from_vulnerabilities(end_points, vulnerabilities)
    service_for_the_node = [serviceid]
    firewall: model.FirewallConfiguration = create_firewall_rules(service_for_the_node)
    properties: List[model.PropertyName] = \
        get_properties_from_vulnerabilities(os_type, vulnerabilities, service_for_the_node)
    return model.NodeInfo(services=[model.ListeningService(name=p) for p in service_for_the_node],
                          vulnerabilities=vulnerabilities,
                          value=100,#random.randint(10,100),
                          properties=properties,
                          firewall=firewall,
                          agent_installed=False)

def generate_node_with_info(
    size_N: int,
    serviceid: str
) -> nx.DiGraph:

    nodes: Dict[str, model.NodeInfo] = {}
    os_types: List[str] = ["Linux", "Windows", "Ubuntu"]
    vuls = [
        {
        # "CVE-2021-25646":
        #     model.VulnerabilityInfo(
        #         description="Apache Druid " + serviceid,
        #         type=model.VulnerabilityType.REMOTE,
        #         URL="https://nvd.nist.gov/vuln/detail/cve-2021-25646",
        #         precondition=model.Precondition(f""+serviceid),
        #         outcome=model.LateralMove(),
        #         rates=model.Rates(0, 0.2, 1.0))
        },
        {
        # "CVE-2021-25646":
        #     model.VulnerabilityInfo(
        #         description="Apache Druid" + serviceid,
        #         type=model.VulnerabilityType.REMOTE,
        #         URL="https://nvd.nist.gov/vuln/detail/cve-2021-25646",
        #         precondition=model.Precondition(f""+serviceid),
        #         outcome=model.LateralMove(),
        #         rates=model.Rates(0, 0.2, 1.0))
        }
    ]
    print(vuls)
    
    for i in range(size_N):
        rand_os: str = os_types[random.randint(0, 1)]
        vul = vuls[i]
        nodes[str(i)] = create_random_node_info(rand_os, potential_ports, vul, serviceid)

    return nodes



def combine_node_info_with_topology_graph(nodes_info: Dict[str, model.NodeInfo], topology_graph: Dict[int, list], serviceid)->nx.DiGraph:
    graph = nx.DiGraph() 
    graph.add_nodes_from([(k, {'data': v}) for (k, v) in list(nodes_info.items())])

    # entry_node_index = 0
    # entry_node_id, entry_node_data = list(graph.nodes(data=True))[entry_node_index]
    # graph.nodes[entry_node_id].clear()  
    
    for node1 in graph.nodes:
        if node1 in topology_graph:
            # print(node1, node2, isinstance(node1, str), (node1, node2) in topology_graph)
            graph.nodes[node1]["data"].vulnerabilities["Scan"] =  model.VulnerabilityInfo(
            description="scan and find a node",
            type=model.VulnerabilityType.LOCAL,
            outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node=topology_graph[node1], port=serviceid, credential = 'credentialport')]),
                                
            reward_string="new node discovered!",
            cost=1.0)
            graph.nodes[topology_graph[node1]]["data"].services.append(model.ListeningService(serviceid, allowedCredentials=['credentialport'])) 
    graph.nodes[str(0)]["data"].agent_installed = True
    return graph


def new_environment(size_N: int):
    """Create a new simulation environment based on a designed generated network topology.

    NOTE: the probabilities and parameter values used
    here for the statistical generative model
    were arbirarily picked. We recommend exploring different values for those parameters.
    """
    print(size_N,"d")
    serviceid = str(random.randint(90, 99))
    print("iiiii", serviceid)
    node_graph = generate_node_with_info(size_N, serviceid)

    # topology_graph = creat_topology_of_a_network(size_N)
    
    topology_graph = {"0": "1"}
    graph = combine_node_info_with_topology_graph(node_graph, topology_graph,serviceid)
    # print("why")
    # print(size_N,"s")
    for i in range(size_N):
        print(graph.nodes[str(i)])
    return model.Environment(network=graph,
                         vulnerability_library=dict([]),
                         identifiers=ENV_IDENTIFIERS)

# g1 = new_environment(2)