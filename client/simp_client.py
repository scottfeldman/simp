#!/usr/bin/env python

import socket
import pickle
import struct

class SimpClientError(Exception): pass

class SimpClient(socket.socket):

    """Simple Network Simulator Client

    The simulation network topology is described with a Graphviz .dot
    unidirectional graph.  The graph describes edges, where each edge
    connects two nodes.  Each node is instantiated as a virtual machine
    (VM) in the simulation.  Node interfaces represent the end points
    of the edges connecting nodes.  Node interfaces are instantiated as
    network interfaces on the VM.  The network interface names and the
    name of the nodes are derived from the .dot edge descriptions.
    """

    def __init__(self, host="localhost", port=6667):

        """Create new client connection to host

        :param host: Server host name
        :type host: String
        :param port: Server port
        :type port: String
        """

        self.handle = None

        try:
            socket.socket.__init__(self, socket.AF_INET, socket.SOCK_STREAM)
            self.connect((host, port))

        except socket.error, (errno, string):
            raise SimpClientError("socket err [%d]: %s" % (errno, string))

    def _request(self, args):

        try:
            pargs = pickle.dumps(args, pickle.HIGHEST_PROTOCOL)
            self.sendall(struct.pack('I', len(pargs)))
            self.sendall(pargs)

            buf = ""
            while len(buf) < 4:
                chunk = self.recv(4 - len(buf))
                if not chunk:   # EOF
                    return False
                buf += chunk

            ret_len = int(struct.unpack('I', buf)[0])

            buf = ""
            while len(buf) < ret_len:
                chunk = self.recv(max(2048, ret_len - len(buf)))
                if not chunk:   # EOF
                    return False
                buf += chunk

            out, err = pickle.loads(buf)
            if err:
                raise SimpClientError(err)
            return out

        except socket.error, (errno, string):
            raise SimpClientError("socket err [%d]: %s" % (errno, string))

    def create(self, sim_name, dot_data, options=[]):

        """Create new simulation.

        Nodes' VM disks are created by making copies of the base_img.
        Nodes are not started until the start() method is called. On
        return, client is attached to newly created simulation.

        :param sim_name: Simulation name
        :type sim_name: String
        :param dot_data: String containing Graphviz .dot unidirectional
            graph description
        :type dot_data: Multi-line String
        :param options: Node options
        :type options: List of node:option:value tuples
        """

        self.handle = self._request(("create", sim_name,
            dot_data, options))

    def create_image(self, node_name):

        """Create disk image for node.

        :param node_name: Node name
        :type node_name: String
        """

        self._request(("create_image", self.handle, node_name))

    def destroy(self):

        """Destroy simulation.

        All (running) nodes are stopped and node's VM disk images are
        destroyed.
        """

        self._request(("destroy", self.handle))
        self.handle = None

    def attach(self, sim_name):

        """Attach client to a previously created simulation

        :param sim_name: Simulation name
        :type sim_name: String
        """

        self.handle = self._request(("attach", sim_name))

    def start(self, node_name):

        """Start node

        :param node_name: Node name
        :type node_name: String
        """

        self._request(("start", self.handle, node_name))

    def stop(self, node_name):

        """Stop node

        :param node_name: Node name
        :type node_name: String
        """

        self._request(("stop", self.handle, node_name))

    def link_ctrl(self, node_name, intf_name, up_down):

        self._request(("link_ctrl", self.handle, node_name,
            intf_name, up_down))

    def get_sim_list(self):

        """Return list of simulations.

        No need to attach to any particular simulation to get a
        list of simulations that have been previously created.

        :rtype: List of simulation name Strings
        """

        return self._request(("get_sim_list", None))

    def get_node_names(self):

        """Return list of nodes in simulation

        :rtype: List of node name Strings
        """

        return self._request(("get_node_names", self.handle))

    def get_intf_names(self, node_name):

        """Return list of interface names on simulation node

        :param node_name: Node name
        :type node_name: String
        :rtype: List of interface name Strings
        """

        return self._request(("get_intf_names", self.handle, node_name))

    def get_link_port(self, node_name, intf_name):

        return self._request(("get_link_port", self.handle,
            node_name, intf_name))

    def get_ssh_port(self, node_name):

        """Return SSH port of node.

        Use ssh -p <port> to SSH login to node.

        :param node_name: Node name
        :type node_name: String
        :rtype: Int
        """

        return self._request(("get_ssh_port", self.handle, node_name))

    def get_console_port(self, node_name):

        """Return telnet port of node's console.

        Use telnet <host> <port> to telnet into node's console.

        :param node_name: Node name
        :type node_name: String
        :rtype: Int
        """

        return self._request(("get_console_port", self.handle, node_name))

    def get_monitor_port(self, node_name):

        """Return telnet port of node's KVM monitor.

        Use telnet <host> <port> to telnet into node's KVM monitor.

        :param node_name: Node name
        :type node_name: String
        :rtype: Int
        """

        return self._request(("get_monitor_port", self.handle, node_name))

    def get_status(self):

        """Return status of simulation

        Key-value pairs are returned

        | Name = <simulation name>
        | Created = <data/time simulation created>
        | Nodes = <count of nodes in simulation>
        | Running? = <Yes|No>

        :rtype: Multi-Line String
        """

        return self._request(("get_status", self.handle))

    def get_node_status(self, node_name):

        """Return status of node

        Key-value pairs are returned

        | Name = <node name>
        | Number = <node number>
        | Interface = <count of node interfaces>
        | Running? = <node VM is running? Yes|No>
        | SSH? = <node SSH port is active? Yes|No>
        | SSH port = <port>
        | Console port = <port>
        | Monitor port = <port>
        | Eth0 MAC = <eth0 MAC address>

        :param node_name: Node name
        :type node_name: String
        :rtype: Multi-Line String
        """

        return self._request(("get_node_status", self.handle, node_name))

    def get_intf_status(self, node_name, intf_name):

        """Return status of simulation.

        Destination/source ports are the UDP socket ports used to
        connect the interface to the neighboring node.  Each graph
        edge has two UDP sockets to allow bidirectional traffic
        between nodes.  The desination port is the node's interface's
        bound socket port number.  The source port is the neighboring
        node's interface's connected socket port number::

        \+--------+                        +--------+
        \| node1  |dst port        src port| node2  |
        \|      +-|----------->>-----------|-+      |
        \|  intf| |                        | |intf  |
        \|      | |src port        dst port| |      |
        \|      +-|-----------<<-----------|-+      |
        \|        |                        |        |
        \+--------+                        +--------+

        Key-value pairs are returned:

        | Name = <interface name>
        | MAC = <interface MAC address>
        | Dst Port = <dst UDP port>
        | Src Port = <src UDP port>

        :param node_name: Node name
        :type node_name: String
        :param intf_name: Interface name
        :type intf_name: String
        :rtype: Multi-Line String
        """

        return self._request(("get_intf_status", self.handle,
            node_name, intf_name))

    def get_node_type(self, node_name):

        """Return type of node

        :param node_name: Node name
        :type node_name: String
        :returns: Type of node
        :rtype: String
        """

        return self._request(("get_node_type", self.handle, node_name))
