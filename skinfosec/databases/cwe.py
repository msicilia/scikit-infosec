#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Fri Nov 25 12:54:19 2016

@author: migueld
"""

from lxml import objectify

class CWE(object):
    
    """A representation of the CWE hierarchi.
    """
    
    list_cwe_nodes = []
    
    def __init__(self, url):
        """Create a representation of the Common Vulnerabilities and
        Exposures (CVE) database from the NVD Data Feeds:
        https://nvd.nist.gov/download.cfm
        """
        self.url = url
        xml = open(url, "r").read()
        self.tree = objectify.fromstring(xml)
        self.calc_nodes()
        self.calc_relationships()
    
    def get_tree(self):
        return self.tree
        
    def calc_nodes(self):
        for node in self.tree["Categories"]["Category"]:
            
            ID = str(node.attrib["ID"])
            name = node.attrib["Name"]
            status = node.attrib["Status"]
            description = node["Description"]["Description_Summary"]

            cwe_node = CWE_Node(ID, name, status, description, "Category")
            self.list_cwe_nodes.append(cwe_node)
            
        for node2 in self.tree["Weaknesses"]["Weakness"]:
            
            ID = str(node2.attrib["ID"])
            name = node2.attrib["Name"]
            status = node2.attrib["Status"]
            description = node2["Description"]["Description_Summary"]

            cwe_node2 = CWE_Node(ID, name, status, description, "Weakness")
            self.list_cwe_nodes.append(cwe_node2)

    def calc_relationships(self):
        for node in self.tree["Categories"]["Category"]:
            
            ID = node.attrib["ID"]
            #print("ID = "+ ID)  
            
            
            if node.find("Relationships") is not None:
                for relationship in node["Relationships"]["Relationship"]:
                    relationship_target_id = str(relationship["Relationship_Target_ID"])
                    relationship_nature = relationship["Relationship_Nature"]

                    #print("Target ID: " + relationship_target_id)

                    if relationship_nature == "CanAlsoBe":
                        self.get_node(ID).add_can_also_be(relationship_target_id)
                        
                    elif relationship_nature == "CanPrecede":
                        self.get_node(ID).add_can_precede(relationship_target_id)
                        self.get_node(relationship_target_id).add_can_follow(ID)
                        
                    elif relationship_nature == "ChildOf":
                        self.get_node(ID).add_parent(relationship_target_id)
                        self.get_node(relationship_target_id).add_child(ID)               

                    elif relationship_nature == "PeerOf":
                        self.get_node(ID).add_peer_of(relationship_target_id)
                        
        for node2 in self.tree["Weaknesses"]["Weakness"]:
            
            ID = node2.attrib["ID"]
            #print("ID = "+ ID)  
            
            
            if node2.find("Relationships") is not None:
                for relationship in node2["Relationships"]["Relationship"]:
                    relationship_target_id = str(relationship["Relationship_Target_ID"])
                    relationship_nature = relationship["Relationship_Nature"]

                    #print("Target ID: " + relationship_target_id)

                    if relationship_nature == "CanAlsoBe":
                        self.get_node(ID).add_can_also_be(relationship_target_id)
                        
                    elif relationship_nature == "CanPrecede":
                        self.get_node(ID).add_can_precede(relationship_target_id)
                        self.get_node(relationship_target_id).add_can_follow(ID)
                        
                    elif relationship_nature == "ChildOf":
                        self.get_node(ID).add_parent(relationship_target_id)
                        self.get_node(relationship_target_id).add_child(ID)               

                    elif relationship_nature == "PeerOf":
                        self.get_node(ID).add_peer_of(relationship_target_id)
            
            
    def __getitem__(self, ID):
        """Get the CWE node with the given id.
        """
        for cwe_node in self.list_cwe_nodes:
            if(cwe_node.ID == ID):
                return cwe_node
        pass
    
    def get_node(self, ID):
        """Get the CWE node with the given id.
        """
        for cwe_node in self.list_cwe_nodes:
            if(cwe_node.ID == ID):
                return cwe_node
        print("No ha encontrado el nodo: "+str(ID))

class CWE_Node(object):
    
    
    
    
    def __init__(self, ID, name, status, description, form):
        self.ID = ID
        self.name = name
        self.status = status
        self.description = description
        self.form = form
        self.child_of_list = set()
        self.can_follow_list = set()
        self.parents_list = set()
        self.can_precede_list = set()
        self.can_also_be_list = set()
        self.peer_of_list = set()
    
    def add_child(self, node):
        self.child_of_list.add(node)
    
    def add_can_follow(self, node):
        self.can_follow_list.add(node)
    
    def add_parent(self, node):
        self.parents_list.add(node)
        
    def add_can_precede(self, node):
        self.can_precede_list.add(node)
        
    def add_can_also_be(self, node):
        self.can_also_be_list.add(node)
        
    def add_peer_of(self, node):
        self.peer_of_list.add(node)
        
        
    def to_string(self):
        result = "CWE ID: " + str(self.ID) + "\n"
        result += "-Name: " + str(self.name) + "\n"
        result += "-Status: " + str(self.status) + "\n"
        result += "-Form: " + str(self.form) + "\n"
        result += "-Description: " + str(self.description) + "\n"
        result += "-Parents: " + str(self.parents_list) + "\n"
        result += "-Children: " + str(self.child_of_list) + "\n"
        result += "-CanPrecede: " + str(self.can_precede_list) + "\n"
        result += "-CanFollow: " + str(self.can_follow_list) + "\n"
        result += "-CanAlsoBe: " + str(self.can_also_be_list) + "\n"
        result += "-PeerOf: " + str(self.peer_of_list) + "\n"
        
        print(result)
        
        