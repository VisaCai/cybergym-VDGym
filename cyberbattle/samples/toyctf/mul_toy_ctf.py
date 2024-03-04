import random
import re
import networkx as nx
import numpy as np
import sys
sys.path.append("/home/kalic/Desktop/AI_P/CyberBattleSim")
from cyberbattle.simulation import model
from cyberbattle.simulation.model import Identifiers, NodeID, CredentialID, PortName, FirewallConfiguration, FirewallRule, RulePermission, NodeInfo, VulnerabilityID, VulnerabilityInfo
import itertools as itts
from typing import Dict, Iterator, cast, Tuple, List, Set
import collections as col
import copy

ADMINTAG = model.AdminEscalation().tag
SYSTEMTAG = model.SystemEscalation().tag
default_allow_rules = [
    model.FirewallRule("RDP", model.RulePermission.ALLOW),
    model.FirewallRule("SSH", model.RulePermission.ALLOW),
    model.FirewallRule("HTTPS", model.RulePermission.ALLOW),
    model.FirewallRule("HTTP", model.RulePermission.ALLOW)]

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

    # topology_graph = nx.DiGraph()
    # for (u, v) in network_edges:
    #     topology_graph.add_edge(u, v)    
    # print(size_NGN_dis_type_list, topology_graph.nodes, topology_graph.edges)
    return network_edges

def creat_new_topo_for_toy(size_N, size_NGN, dis_type, network_cc, connect_percent):    
    newtopo = creat_topology_of_a_network(size_N, size_NGN, dis_type, network_cc, connect_percent)
    nodenames = ["Website", "Website.Directory", "Website[user=monitor]", "GitHubProject", "AzureStorage", "Sharepoint", "AzureResourceManager", "AzureResourceManager[user=monitor]","AzureVM"]
    
    old_to_new_list = {}
    old_to_new_list["0"] = "client"
    newlist = list(range(1,10))
    random.shuffle(newlist)
    for idi, nodename in zip(newlist, nodenames):
        old_to_new_list[str(idi)] = nodename

    newtopodict = {}
    for keyi, valuei in newtopo.items():
        newtopodict[old_to_new_list[keyi]] = [old_to_new_list[vi] for vi in valuei]
    return old_to_new_list, newtopodict


nodes = {
    "Website": model.NodeInfo(
        services=[model.ListeningService("HTTPS"),
                  model.ListeningService("SSH", allowedCredentials=[
                      "ReusedMySqlCred-web"])],
        firewall=model.FirewallConfiguration(incoming=default_allow_rules,
                                         outgoing=default_allow_rules + [
                                             model.FirewallRule("su", model.RulePermission.ALLOW),
                                             model.FirewallRule("sudo", model.RulePermission.ALLOW)]),
        value=100,
        # If can SSH into server then gets FLAG "Shared credentials with
        # database user"
        properties=["MySql", "Ubuntu", "nginx/1.10.3"],
        owned_string="FLAG: Login using insecure SSH user/password",
        vulnerabilities=dict(
            ScanPageContent=model.VulnerabilityInfo(
                description="LeakedGitHubProjectUrl: Website page content shows a link to GitHub "
                            "repo",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.LeakedNodesId(["GitHubProject"]),
                reward_string="WEBSITE page content has a link to github -> Github project discovered!",
                cost=1.0
            ),
            ScanPageSource=model.VulnerabilityInfo(
                description="Website page source contains refrence to browseable "
                            "relative web directory",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.LeakedNodesId(["Website.Directory"]),
                reward_string="Viewing the web page source reveals a URL to a .txt file and directory on the website",
                cost=1.0
            ),
            CredScanBashHistory=model.VulnerabilityInfo(
                description="bash history leaking creds - FLAG Stealing "
                            "credentials for the monitoring user",
                type=model.VulnerabilityType.LOCAL,
                outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node="Website[user=monitor]", port="SSH",
                                       credential="monitorBashCreds")]),
                reward_string="FLAG: SSH history revealed credentials for the monitoring user (monitor)",
                cost=1.0
            ))),

    "Website.Directory": model.NodeInfo(
        services=[model.ListeningService("HTTPS")],
        value=50,
        properties=["Ubuntu", "nginx/1.10.3",
                    "CTFFLAG:Readme.txt-Discover secret data"
                    ],
        vulnerabilities=dict(
            NavigateWebDirectoryFurther=model.VulnerabilityInfo(
                description="Discover MYSQL credentials MySql for user "
                            "'web' in (getting-started.txt)",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node="Website", port="MySQL",
                                       credential="ReusedMySqlCred-web")]),
                reward_string="Discover browseable web directory: Navigating to parent URL revealed file `readme.txt`"
                              "with secret data (aflag); and `getting-started.txt` with MYSQL credentials",
                cost=1.0
            ),
            NavigateWebDirectory=model.VulnerabilityInfo(
                description="Discover URL to external sharepoint website "
                            "(in deprecation-checklist.txt)",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.LeakedNodesId(["Sharepoint"]),
                reward_string="Navigating to parent URL revealed file `deprecation-checklist.txt` containing"
                              "a URL to an external sharepoint website",
                cost=1.0
            )
        )),

    "Website[user=monitor]": model.NodeInfo(
        services=[model.ListeningService("SSH", allowedCredentials=[]),
                  model.ListeningService("SSH-key", allowedCredentials=["unkownkey"]),
                  model.ListeningService("su", allowedCredentials=["monitorBashCreds"])],
        value=100,
        properties=["MySql", "Ubuntu", "nginx/1.10.3"],
        owned_string="FLAG User escalation by stealing credentials from bash history",
        firewall=model.FirewallConfiguration(
            outgoing=default_allow_rules,
            incoming=[model.FirewallRule("SSH", model.RulePermission.BLOCK,
                                     reason="password authentication disabled! SSH needs private key to authenticate."),
                      model.FirewallRule("sudo", model.RulePermission.BLOCK,
                                     reason="`sudo -u monitor` failed. User 'monitor' not sudoable."
                                            "This warning will be reported!"),
                      model.FirewallRule("su", model.RulePermission.ALLOW)] + default_allow_rules
        ),
        vulnerabilities={
            "CredScan-HomeDirectory":
                model.VulnerabilityInfo(
                    description="azurecredential.txt file in home directory",
                    type=model.VulnerabilityType.LOCAL,
                    outcome=model.LeakedCredentials(credentials=[
                        model.CachedCredential(
                                node="AzureResourceManager[user=monitor]",
                                port="HTTPS",
                                credential="azuread_user_credentials")]),
                    reward_string="SSH: cat ~/azurecreds.txt (running as monitor) revealed Azure user credential!",
                    cost=1.0),
        }),

    "GitHubProject": model.NodeInfo(
        services=[model.ListeningService("GIT")],
        value=10,
        properties=["GitHub", "SasUrlInCommit"],
        vulnerabilities=dict(
            CredScanGitHistory=model.VulnerabilityInfo(
                description="Some secure access token (SAS) leaked in a "
                "reverted git commit",
                type=model.VulnerabilityType.REMOTE,
                precondition=model.Precondition('SasUrlInCommit&GitHub'),
                outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node="AzureStorage",
                                       port="HTTPS",
                                       credential="SASTOKEN1")]),
                rates=model.Rates(probingDetectionRate=0.0,
                              exploitDetectionRate=0.0,
                              successRate=1.0),
                reward_string="CredScan success: Some secure access token (SAS) was leaked in a reverted git commit",
                cost=1.0
            ))),

    "AzureStorage": model.NodeInfo(
        services=[
            model.ListeningService("HTTPS", allowedCredentials=["SASTOKEN1"])],
        value=50,
        properties=["CTFFLAG:LeakedCustomerData"],
        vulnerabilities=dict(
            AccessDataWithSASToken=model.VulnerabilityInfo(
                description="Stealing secrets using a publicly shared "
                            "SAS token",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.CustomerData(),
                rates=model.Rates(successRate=1.0),
                reward_string="Stole data using a publicly shared SAS token",
                cost=1.0
            )
        )),

    "Sharepoint": model.NodeInfo(
        services=[model.ListeningService("HTTPS")],
        value=100,
        properties=["SharepointLeakingPassword"],
        firewall=model.FirewallConfiguration(incoming=[model.FirewallRule("SSH", model.RulePermission.ALLOW),
                                                   model.FirewallRule("HTTP", model.RulePermission.ALLOW),
                                                   model.FirewallRule("HTTPS", model.RulePermission.ALLOW)],
                                         outgoing=[]),
        vulnerabilities=dict(
            ScanSharepointParentDirectory=model.VulnerabilityInfo(
                description="Navigate to SharePoint site, browse parent "
                            "directory",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.LeakedCredentials(credentials=[
                    model.CachedCredential(node="AzureResourceManager",
                                       port="HTTPS",
                                       credential="ADPrincipalCreds")]),
                rates=model.Rates(successRate=1.0),
                reward_string="Navigating to the Sharepoint site revealed  AD Service Principal Credentials",
                cost=1.0)
        )),

    "AzureResourceManager": model.NodeInfo(
        services=[model.ListeningService("HTTPS", allowedCredentials=["ADPrincipalCreds", "azuread_user_credentials"])],
        owned_string="FLAG: Shared credentials with database user - Obtained secrets hidden in Azure Managed Resources",
        value=50,
        properties=["CTFFLAG:LeakedCustomerData2"],
        vulnerabilities=dict(
            ListAzureResources=model.VulnerabilityInfo(
                description="AzureVM info, including public IP address",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.LeakedNodesId(["AzureVM"]),
                reward_string="Obtained Azure VM and public IP information",
                cost=1.0
            ))),

    'AzureResourceManager[user=monitor]': model.NodeInfo(
        services=[model.ListeningService("HTTPS", allowedCredentials=["azuread_user_credentials"])],
        owned_string="More secrets stolen when logged as interactive `monitor` user in Azure with `az`",
        value=50,
        properties=[],
    ),

    'AzureVM': model.NodeInfo(
        services=[model.ListeningService("PING"),
                  model.ListeningService("SSH")],
        value=100,
        properties=["CTFFLAG:VMPRIVATEINFO"],
        firewall=model.FirewallConfiguration(
            incoming=[model.FirewallRule("SSH", model.RulePermission.BLOCK,
                                     reason="internet incoming traffic blocked on the VM by NSG firewall")],
            outgoing=[])),

    'client': model.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=dict(
            SearchEdgeHistory=model.VulnerabilityInfo(
                description="Search web history for list of accessed websites",
                type=model.VulnerabilityType.LOCAL,
                outcome=model.LeakedNodesId(["Website"]),
                reward_string="Web browser history revealed website URL of interest",
                cost=1.0
            )),
        agent_installed=True,
        reimagable=False),
}

def from_odlnodes_to_newnodes(oldnodes, old_to_new_list, newtopodict)->nx.DiGraph:
    newnodes = nx.DiGraph() 
    newnodes.add_nodes_from([(k, {"data": copy.copy(v)}) for (k, v) in list(oldnodes.items())])

    for i in range(10):
        namei = old_to_new_list[str(i)]
        newnodes.nodes[namei]["data"].services = []
           
    for i in range(10):
        namei = old_to_new_list[str(i)]
        newnodes.nodes[namei]["data"].vulnerabilities = {} 
        for vul in oldnodes[namei].vulnerabilities:
            if isinstance(oldnodes[namei].vulnerabilities[vul].outcome, model.LeakedNodesId):
                typei = oldnodes[namei].vulnerabilities[vul].type
                newnodes.nodes[namei]["data"].vulnerabilities[vul] = model.VulnerabilityInfo(
                    description="Search web history for list of accessed websites",
                    type=typei,
                    outcome=model.LeakedNodesId(newtopodict[namei]),
                    reward_string="Web browser history revealed website URL of interest",
                    cost=1.0)
            elif isinstance(oldnodes[namei].vulnerabilities[vul].outcome, model.LeakedCredentials):
                nextnode = random.choice(newtopodict[namei])
                while nextnode == "client":
                    nextnode = random.choice(newtopodict[namei])
                descriptioni = oldnodes[namei].vulnerabilities[vul].description
                typei = oldnodes[namei].vulnerabilities[vul].type
                nextnode_info = oldnodes[namei].vulnerabilities[vul].outcome.credentials[0]
                rewardi = oldnodes[namei].vulnerabilities[vul].reward_string

                newnodes.nodes[namei]["data"].vulnerabilities[vul] = model.VulnerabilityInfo(
                    description=descriptioni,
                    type=typei,
                    outcome=model.LeakedCredentials(credentials=[
                        model.CachedCredential(node=nextnode, port=nextnode_info.port, credential=nextnode_info.credential)
                    ]),
                    reward_string=rewardi,
                    cost=1.0) 
                newnodes.nodes[nextnode]["data"].services.append(model.ListeningService(nextnode_info.port, allowedCredentials=[
                      nextnode_info.credential])) 
            else:
                newnodes.nodes[namei]["data"].vulnerabilities[vul] = oldnodes[namei].vulnerabilities[vul]
    return newnodes



global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])
# Environment constants
global ENV_IDENTIFIERS
ENV_IDENTIFIERS = model.infer_constants_from_nodes(
cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
global_vulnerability_library)

def new_environment(size_N: int, size_NGN: int, dis_type: str, network_cc: str, connect_percent: float) -> model.Environment:

    old_to_new_list, newtopodict = creat_new_topo_for_toy(size_N, size_NGN, dis_type, network_cc, connect_percent)
    newnodes = from_odlnodes_to_newnodes(nodes, old_to_new_list, newtopodict)

    return model.Environment(
        network=newnodes,
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )

# g1 = new_environment(10, 2,"gradient_up", "chained", 0.9)
# print(g1)