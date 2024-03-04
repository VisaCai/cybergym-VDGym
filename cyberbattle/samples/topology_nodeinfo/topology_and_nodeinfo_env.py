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
    "CVE-2020-3433":
    model.VulnerabilityInfo(
        description= "Zenphoto, HTTP, HTTPs",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2020-433",
        precondition=model.Precondition(f"win7|win8|win10"),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0, 0.2, 1.0)),    
    "CVE-2020-3153":
    model.VulnerabilityInfo(
        description= "Cisco AnyConnect <=4.5.02042",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2020-433",
        precondition=model.Precondition(f"win7|win8|win10"),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0, 0.2, 1.0)),  
    # "UACME43":
    # model.VulnerabilityInfo(
    #     description="UACME UAC bypass #43",
    #     type=model.VulnerabilityType.LOCAL,
    #     URL="https://github.com/hfiref0x/UACME",
    #     precondition=model.Precondition(f"Windows&(Win10|Win7)&(~({ADMINTAG}|{SYSTEMTAG}))"),
    #     outcome=model.AdminEscalation(),
    #     rates=model.Rates(0, 0.2, 1.0)),
    # "UACME45":
    # model.VulnerabilityInfo(
    #     description="UACME UAC bypass #45",
    #     type=model.VulnerabilityType.LOCAL,
    #     URL="https://github.com/hfiref0x/UACME",
    #     precondition=model.Precondition(f"Windows&Win10&(~({ADMINTAG}|{SYSTEMTAG}))"),
    #     outcome=model.AdminEscalation(),
    #     rates=model.Rates(0, 0.2, 1.0)),
    # "UACME52":
    # model.VulnerabilityInfo(
    #     description="UACME UAC bypass #52",
    #     type=model.VulnerabilityType.LOCAL,
    #     URL="https://github.com/hfiref0x/UACME",
    #     precondition=model.Precondition(f"Windows&(Win10|Win7)&(~({ADMINTAG}|{SYSTEMTAG}))"),
    #     outcome=model.AdminEscalation(),
    #     rates=model.Rates(0, 0.2, 1.0)),
    # "UACME55":
    # model.VulnerabilityInfo(
    #     description="UACME UAC bypass #55",
    #     type=model.VulnerabilityType.LOCAL,
    #     URL="https://github.com/hfiref0x/UACME",
    #     precondition=model.Precondition(f"Windows&(Win10|Win7)&(~({ADMINTAG}|{SYSTEMTAG}))"),
    #     outcome=model.AdminEscalation(),
    #     rates=model.Rates(0, 0.2, 1.0)),
    # "UACME61":
    # model.VulnerabilityInfo(
    #     description="UACME UAC bypass #61",
    #     type=model.VulnerabilityType.LOCAL,
    #     URL="https://github.com/hfiref0x/UACME",
    #     precondition=model.Precondition(f"Windows&Win10&(~({ADMINTAG}|{SYSTEMTAG}))"),
    #     outcome=model.AdminEscalation(),
    #     rates=model.Rates(0, 0.2, 1.0)),
    # "MimikatzLogonpasswords":
    # model.VulnerabilityInfo(
    #     description="Mimikatz sekurlsa::logonpasswords.",
    #     type=model.VulnerabilityType.LOCAL,
    #     URL="https://github.com/gentilkiwi/mimikatz",
    #     precondition=model.Precondition(f"Windows&({ADMINTAG}|{SYSTEMTAG})"),
    #     outcome=model.LeakedCredentials([]),
    #     rates=model.Rates(0, 1.0, 1.0)),
    # "MimikatzKerberosExport":
    # model.VulnerabilityInfo(
    #     description="Mimikatz Kerberos::list /export."
    #                 "Exports .kirbi files to be used with pass the ticket",
    #     type=model.VulnerabilityType.LOCAL,
    #     URL="https://github.com/gentilkiwi/mimikatz",
    #     precondition=model.Precondition(f"Windows&DomainJoined&({ADMINTAG}|{SYSTEMTAG})"),
    #     outcome=model.LeakedCredentials([]),
    #     rates=model.Rates(0, 1.0, 1.0))
}
potential_windows_vulns_remote = {
    "CVE-2020-36079":
    model.VulnerabilityInfo(
        description= "Zenphoto, HTTP, HTTPs",
        type=model.VulnerabilityType.REMOTE,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2020-36079",
        precondition=model.Precondition(f"win7|win8|win10|Linux"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 1.0, 1.0)),
    "CVE-2020-2555":
    model.VulnerabilityInfo(
        description= "Oracle weblogic, HTTP, HTTPs",
        type=model.VulnerabilityType.REMOTE,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2020-36079",
        precondition=model.Precondition(f"win7|win8|win10"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 1.0, 1.0))
    # "PassTheTicket":
    # model.VulnerabilityInfo(
    #     description="Mimikatz Kerberos::ptt /export."
    #                 "Exports .kirbi files to be used with pass the ticket",
    #     type=model.VulnerabilityType.REMOTE,
    #     URL="https://github.com/gentilkiwi/mimikatz",
    #     precondition=model.Precondition(f"Windows&DomainJoined&KerberosTicketsDumped"
    #                                     f"&({ADMINTAG}|{SYSTEMTAG})"),
    #     outcome=model.LeakedCredentials([]),
    #     rates=model.Rates(0, 1.0, 1.0)),
    # "RDPBF":
    # model.VulnerabilityInfo(
    #     description="RDP Brute Force",
    #     type=model.VulnerabilityType.REMOTE,
    #     URL="https://attack.mitre.org/techniques/T1110/",
    #     precondition=model.Precondition("Windows&PortRDPOpen"),
    #     outcome=model.LateralMove(),
    #     rates=model.Rates(0, 0.2, 1.0)),

    # "SMBBF":
    # model.VulnerabilityInfo(
    #     description="SSH Brute Force",
    #     type=model.VulnerabilityType.REMOTE,
    #     URL="https://attack.mitre.org/techniques/T1110/",
    #     precondition=model.Precondition("(Windows|Linux)&PortSMBOpen"),
    #     outcome=model.LateralMove(),
    #     rates=model.Rates(0, 0.2, 1.0))
}

potential_linux_vulns_remote = {
    # "SudoCaching":
    # model.VulnerabilityInfo(
    #     description="Escalating privileges from poorly configured sudo on linux/unix machines",
    #     type=model.VulnerabilityType.REMOTE,
    #     URL="https://attack.mitre.org/techniques/T1206/",
    #     precondition=model.Precondition(f"Linux&(~{ADMINTAG})"),
    #     outcome=model.AdminEscalation(),
    #     rates=model.Rates(0, 1.0, 1.0)),
    "SSHBF":
    model.VulnerabilityInfo(
        description="SSH Brute Force",
        type=model.VulnerabilityType.REMOTE,
        URL="https://attack.mitre.org/techniques/T1110/",
        precondition=model.Precondition(f"Linux&PortSSHOpen"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 0.2, 1.0)),
    "SMBBF":
    model.VulnerabilityInfo(
        description="SSH Brute Force",
        type=model.VulnerabilityType.REMOTE,
        URL="https://attack.mitre.org/techniques/T1110/",
        precondition=model.Precondition(f"(Windows|Linux)&PortSMBOpen"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 0.2, 1.0))
}

potential_linux_vulns_local = {
    "CVE-2021-4034":
    model.VulnerabilityInfo(
        description="Polkit",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/cve-2021-4034",
        precondition=model.Precondition(f"(Ubuntu|Linux)&Polkit"),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0, 0.2, 1.0)),
}

potential_Ubuntu_vulns_local = {
    "CVE-2021-4034":
    model.VulnerabilityInfo(
        description="Polkit",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/cve-2021-4034",
        precondition=model.Precondition(f"(Ubuntu|Linux)&Polkit"),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0, 0.2, 1.0)),
    "CVE-2017-16995":
    model.VulnerabilityInfo(
        description="NO",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/cve-2017-16995",
        precondition=model.Precondition(f"(Ubuntu)"),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0, 0.2, 1.0)),
}

potential_ubuntu_vulns_remote = {
    "CVE-2019-2729":
    model.VulnerabilityInfo(
        description="HTTP",
        type=model.VulnerabilityType.LOCAL,
        URL="https://nvd.nist.gov/vuln/detail/cve-2019-2729",
        precondition=model.Precondition(f"(Ubuntu)"),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0, 0.2, 1.0)),
}

potential_scan = {
    "Scan":
    model.VulnerabilityInfo(
        description="Scan to find node",
        type=model.VulnerabilityType.REMOTE,
        URL="",
        precondition=model.Precondition(f"win7|win8|win10|Linux"),
        outcome=model.LeakedNodesId([]),
        rates=model.Rates(0, 0.2, 1.0)),
}
potential_service_vulns = {
    "CVE-2021-25646":
    model.VulnerabilityInfo(
        description="Apache Druid =< 0.20.0",
        type=model.VulnerabilityType.REMOTE,
        URL="https://nvd.nist.gov/vuln/detail/cve-2021-25646",
        precondition=model.Precondition(f"(Ubuntu|Linux)&Apache"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 0.2, 1.0)),
    "CVE-2020-35949":
    model.VulnerabilityInfo(
        description="WordPress Quiz and Survey Master plugin =< 7.0.1, HTTP, HTTPS",
        type=model.VulnerabilityType.REMOTE,
        URL="https://nvd.nist.gov/vuln/detail/CVE-2020-35949",
        precondition=model.Precondition(f"(Ubuntu|Linux)&WordPress"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 0.2, 1.0)),
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
    properties=potential_linux_node_states + potential_windows_node_states,
    local_vulnerabilities=list(potential_windows_vulns_local.keys()) + \
        list(potential_linux_vulns_local.keys()) + list(potential_Ubuntu_vulns_local.keys()) + list(potential_scan.keys()),
    remote_vulnerabilities=list(potential_windows_vulns_remote.keys()) + \
    list(potential_linux_vulns_remote.keys()) + list(potential_ubuntu_vulns_remote.keys()) 
)

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
            size_NGN_dis_type[i] = size_NGN_dis_type[i-1] + 1 + (dis_mod > 1)
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

    # topology_graph = nx.DiGraph()
    # for (u, v) in network_edges:
    #     topology_graph.add_edge(u, v)    
    # print(size_NGN_dis_type_list, topology_graph.nodes, topology_graph.edges)
    return network_edges

def select_random_vulnerabilities(os_type: str, local_num: int, remote_num:int) \
        -> Dict[str, model.VulnerabilityInfo]:
    """
        It takes an a string for the OS type,  and an int for the number of
        vulnerabilities to select.

        It selects num_vulns vulnerabilities from the global list of vulnerabilities for that
        specific operating system.  It returns a dictionary of VulnerabilityInfo objects to
        the caller.
    """

    if remote_num < 1 :
        raise ValueError("Expected a positive value for num_vulns in select_random_vulnerabilities")

    ret_val: Dict[str, model.VulnerabilityInfo] = {}
    keys: List[str]
    if os_type == "Linux":
        local_keys = random.sample(list(potential_linux_vulns_local.keys()), local_num)
        remote_keys = random.sample(list(potential_linux_vulns_remote.keys()), remote_num)
        keys = local_keys + remote_keys
        ret_val = {k: potential_linux_vulns_local[k] if k in potential_linux_vulns_local else potential_linux_vulns_remote[k] for k in keys} 
    elif os_type == "Windows":
        local_keys = random.sample(list(potential_windows_vulns_local.keys()), local_num)
        remote_keys = random.sample(list(potential_windows_vulns_remote.keys()), remote_num)
        keys = local_keys + remote_keys
        ret_val = {k: potential_windows_vulns_local[k] if k in potential_windows_vulns_local else potential_windows_vulns_remote[k] for k in keys} 
    elif os_type == "Ubuntu":
        local_keys = random.sample(list(potential_ubuntu_vulns_local.keys()), local_num)
        remote_keys = random.sample(list(potential_ubuntu_vulns_remote.keys()), remote_num)
        keys = local_keys + remote_keys
        ret_val = {k: potential_ubuntu_vulns_local[k] if k in potential_ubuntu_vulns_local else potential_ubuntu_vulns_remote[k] for k in keys} 
    else:
        raise ValueError("Invalid Operating System supplied to select_random_vulnerabilities")
    return ret_val

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

def create_random_node_info(os_type: str, end_points: List[model.PortName]) \
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

    # get the vulnerability dictionary for the important OS
    vulnerabilities: model.VulnerabilityLibrary = dict([])
    if os_type == "Linux":
        vulnerabilities = \
            select_random_vulnerabilities(os_type, random.randint(1, len(potential_linux_vulns_local)), random.randint(1, len(potential_linux_vulns_remote)))
    elif os_type == "Windows":
        vulnerabilities = \
            select_random_vulnerabilities(os_type, random.randint(1, len(potential_windows_vulns_local)), random.randint(1, len(potential_windows_vulns_remote)))
    else:
        vulnerabilities = \
            select_random_vulnerabilities(os_type, random.randint(1, len(potential_Ubuntu_vulns_local)), random.randint(1, len(potential_ubuntu_vulns_remote)))

    service_for_the_node = get_service_from_vulnerabilities(end_points, vulnerabilities)
    firewall: model.FirewallConfiguration = create_firewall_rules(service_for_the_node)
    properties: List[model.PropertyName] = \
        get_properties_from_vulnerabilities(os_type, vulnerabilities)
    return model.NodeInfo(services=[model.ListeningService(name=p) for p in service_for_the_node],
                          vulnerabilities=vulnerabilities,
                          value=random.randint(10,100),
                          properties=properties,
                          firewall=firewall,
                          agent_installed=False)

def generate_node_with_info(
    size_N: int
) -> nx.DiGraph:

    nodes: Dict[str, model.NodeInfo] = {}
    os_types: List[str] = ["Linux", "Windows", "Ubuntu"]
    for i in range(size_N):
        rand_os: str = os_types[random.randint(0, 1)]
        nodes[str(i)] = create_random_node_info(rand_os, potential_ports)

    return nodes

def combine_node_info_with_topology_graph(nodes_info: Dict[str, model.NodeInfo], topology_graph: Dict[int, list])->nx.DiGraph:
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
            outcome=model.LeakedNodesId(topology_graph[node1]),
            reward_string="new node discovered!",
            cost=1.0)
    graph.nodes[str(0)]["data"].agent_installed = True
    return graph



def new_environment(size_N: int, size_NGN: int, dis_type: str, network_cc: str, connect_percent: float):
    """Create a new simulation environment based on a designed generated network topology.

    NOTE: the probabilities and parameter values used
    here for the statistical generative model
    were arbirarily picked. We recommend exploring different values for those parameters.
    """
    print(size_N,"d")
    node_graph = generate_node_with_info(size_N)

    topology_graph = creat_topology_of_a_network(size_N, size_NGN, dis_type, network_cc, connect_percent)
    
    graph = combine_node_info_with_topology_graph(node_graph, topology_graph)
    # print("why")
    # print(size_N,"s")
    for i in range(size_N):
        print(graph.nodes[str(i)])
    return model.Environment(network=graph,
                         vulnerability_library=dict([]),
                         identifiers=ENV_IDENTIFIERS)

# g1 = new_environment(7, 2,"gradient_up", "chained", 0.9)