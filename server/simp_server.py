#!/usr/bin/env python

import socket
import pickle
import struct
import select
import pydot
import os
import sys
import subprocess
import logging
import argparse
import signal
import lockfile
from time import *
from traceback import format_exc
import config

logger = logging.getLogger(__name__)
done = False

class SimpIntf(object):

    def __init__(self, name, node):

        self.name = name
        self.node = node
        self.port = None
        self.opposite = None
        self.mac = None

    def get_status(self):

        out = ""
        out += "Name = %s\n" % self.name
        out += "MAC = %s\n" % self.mac
        out += "Dst Port = %s\n" % self.port
        out += "Src Port = %s\n" % self.opposite.port
        return out

class SimpNodeError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)
        logger.critical(message)

class SimpNode(object):

    def __init__(self, sim, name, node_type, options={}):

        self.sim = sim
        self.name = name
        self.node_type = node_type
        self.options = options
        self.intfs = []
        self.number = None
        self.ssh_port = None
        self.console_port = None
        self.monitor_port = None
        self.base_img = None
        self.started = None

    def swp_mac(self, intf): return None
    def create_image(self): pass
    def start(self): pass
    def stop(self): pass

class SimpNodeQemu(SimpNode):

    def eth_mac(self, intf):

        return "00:01:00:%02x:%02x:%02x" % \
            ((self.number >> 8) & 0xff, self.number & 0xff, intf)

    def swp_mac(self, intf):

        return "00:02:00:%02x:%02x:%02x" % \
            ((self.number >> 8) & 0xff, self.number & 0xff, intf)

    def running(self):

        if not self.monitor_port: return False
        ret = subprocess.call("nc -q 1 -z localhost %d" % self.monitor_port, shell=True)
        return ret == 0

    def alive(self):

        if not self.ssh_port: return False
        ret = subprocess.call("echo 'hello' | nc -q 1 localhost %d | grep SSH >/dev/null" % \
            self.ssh_port, shell=True)
        return ret == 0

    def get_status(self):

        out = ""
        out += "Name = %s\n" % self.name
        out += "Number = %s\n" % self.number
        out += "Interfaces = %d\n" % len(self.intfs)
        out += "Running? = %s\n" % ("Yes" if self.running() else "No")
        out += "SSH? = %s\n" % ("Yes" if self.alive() else "No")
        out += "SSH Port = %s\n" % self.ssh_port
        out += "Console Port = %s\n" % self.console_port
        out += "Monitor Port = %s\n" % self.monitor_port
        out += "Eth0 MAC = %s\n" % self.eth_mac(0)
        return out

    def create_image(self):

        if self.base_img:
            raise SimpNodeError("%s: node %s already has disk image" % \
                (self.sim.sim_name, self.name))

        base_img = self.options.get("base", config.dflt_img)

        if os.path.basename(base_img) == base_img:
            self.base_img = config.root_image_dir + '/' + base_img
        else:
            self.base_img = base_img

        if not os.path.exists(self.base_img):
            raise SimpNodeError("%s: base image doesn't exist: %s" % \
                (self.sim.sim_name, self.base_img))

        if self.sim.sim_name != "base":
            cmd = "qemu-img create -b %s -f qcow2 %s/%s.img 40G" % \
                (self.base_img, self.sim.sim_image_dir, self.name)
            out, err = self.sim._run(cmd)
            if err: raise SimpNodeError("%s: %s" % (self.sim.sim_name, err))
            logger.info("%s: created node %s disk image" % \
                (self.sim.sim_name, self.name))

    def start(self):

        if self.started:
            raise SimpNodeError("%s: node %s already started" % \
                (self.sim.sim_name, self.name))

        if self.sim.sim_name == "base":
            image = self.base_img
        else:
            image = "%s.img" % self.name

        cmd = "cd %s && %s -machine accel=kvm" % \
            (self.sim.sim_image_dir, \
             self.options.get("bin", config.dflt_kvm_bin))
        cmd += " -drive file=%s,if=virtio" % image
        cmd += " -name %s" % self.name
        cmd += " -pidfile %s.pid" % self.name
        cmd += " -nographic"
        cmd += " -serial telnet::%d,server,nowait" % self.console_port
        cmd += " -monitor telnet::%d,server,nowait" % self.monitor_port
        cmd += " -m %s" % self.options.get("mem", "256")
        cmd += " -net nic,vlan=10,macaddr=%s,model=virtio" % self.eth_mac(0)
        cmd += " -net user,vlan=10,net=%s,hostfwd=tcp::%d-:22" % \
            (config.ssh_user_net, self.ssh_port)

        def bdf(index):
            starting_slot = 6   # give enough room for earlier qemu devices
            slot = starting_slot + index / 8
            function = index % 8
            multifunction = "on" if function == 0 else "off"
            if slot > 0x1f:
                raise SimpSimError("%s: node %s: ran out of slots on bus 0" % \
                    (self.sim.sim_name, self.name))
            return slot, function, multifunction

        def nic(i, intf):
            dev = "dev%d" % i
            slot, function, multifunction = bdf(i)
            return " -device virtio-net-pci,mac=%s,addr=%d.%d," \
                "multifunction=%s,netdev=%s,id=%s" % \
                (intf.mac, slot, function, multifunction, dev, intf.name)

        def udp_socket(i, intf, opposite):
            dev = "dev%d" % i
            dport = intf.port
            sport = opposite.port
            daddr = saddr = "127.0.0.1"
            return " -netdev socket,udp=%s:%d,localaddr=%s:%d,id=%s" % \
                (daddr, dport, saddr, sport, dev)

        def tap(i, intf, opposite):
            dev = "dev%d" % i
            tap_name = "%s-%s-%s" % \
                (self.sim.sim_name, opposite.node.name, opposite.name)
            if opposite.node.started:
                up_script = config.root_image_dir + "/tap-ifup"
            else:
                up_script = "no"
            return " -netdev tap,id=%s,ifname=%s,script=%s,downscript=no" % \
                (dev, tap_name, up_script)

        def rocker(name, intfs):
            rocker_cmd = " -device rocker,name=%s,len-ports=%d" % \
                (name, len(intfs))
            for i, intf in enumerate(intfs):
                dev = "dev%d" % i
                rocker_cmd += ",ports[%d]=%s" % (i, dev)
            return rocker_cmd

        rocker_name = self.options.get("rocker")
        if (rocker_name):
            cmd += rocker(rocker_name, self.intfs)
        else:
            for i, intf in enumerate(self.intfs):
                cmd += nic(i, intf)

        for i, intf in enumerate(self.intfs):
            if isinstance(intf.opposite.node, SimpNodeNameSpace):
                cmd += tap(i, intf, intf.opposite)
            else:
                cmd += udp_socket(i, intf, intf.opposite)

        self.out_file = open("%s/%s.out" % (self.sim.sim_image_dir, self.name), "a")
        self.out_file.write("\n")
        self.out_file.write("==> started %s\n" % \
            strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime()))
        self.out_file.write("\n")
        self.out_file.write(cmd)
        self.out_file.write("\n\n")
        self.out_file.flush()

        logger.info("%s: starting node '%s'..." % (self.sim.sim_name, self.name))
        self.sim._run(cmd, wait=False, out=self.out_file)

        self.started = time()

    def stop(self):

        if not self.started:
            return

        pid_file = "%s/%s.pid" % (self.sim.sim_image_dir, self.name)
        if os.path.exists(pid_file):
            if os.access(pid_file, os.R_OK):
                pid = open(pid_file).readline().rstrip()
                proc_pid = "/proc/" + str(pid)
                if os.path.exists(proc_pid):

                    logger.info("%s: stopping node '%s'..." % \
                        (self.sim.sim_name, self.name))

                    self.sim._run("echo \"quit\" | telnet localhost %d" % \
                        self.monitor_port)

                    for i in range(10):
                        if not os.path.exists(proc_pid): break
                        sleep(0.1)

                    if os.path.exists(proc_pid):
                        out, err = self.sim._run("kill %s" % pid)

                out, err = self.sim._run("rm %s" % pid_file)

        if self.out_file:
            self.out_file.write("\n")
            self.out_file.write("==> stopped %s\n" % \
                strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime()))
            self.out_file.write("\n")
            self.out_file.close()
            self.out_file = None

        self.started = None

class SimpNodePhysical(SimpNode):

    def set_intf_map(self, intf_map):

        intf_names = [intf.name for intf in self.intfs]
        for intf in intf_map.keys():
            if intf not in intf_names:
                raise SimpNodeError("%s: node %s does not have interface %s;" \
                    " aborting interface map assignment" % \
                    (self.sim.sim_name, self.name, intf))

        self.intf_map = intf_map

class SimpNodeNameSpace(SimpNode):

    def ns(self):
        return self.sim.sim_name + '-' + self.name

    def get_status(self):

        out = ""
        out += "Name = %s\n" % self.name
        out += "Number = %s\n" % self.number
        out += "Interfaces = %d\n" % len(self.intfs)
        out += "Running? = %s\n" % ("Yes" if self.started else "No")
        out += "SSH? = %s\n" % ("Yes" if self.started else "No")
        out += "SSH Port = n/a\n"
        out += "Console Port = n/a\n"
        out += "Monitor Port = n/a\n"
        out += "Eth0 MAC = n/a (namespace)\n"
        return out

    def start(self):

        if self.started:
            raise SimpNodeError("%s: node %s already started" % \
                (self.sim.sim_name, self.name))

        logger.info("%s: starting node '%s'..." % (self.sim.sim_name, self.name))

        ns = self.ns()

        # if there is a left-over namespace, clean it up first

        out, err = self.sim._run("ip netns show | grep %s" % ns)
        if out:
            out, err = self.sim._run("ip netns exec %s ip -oneline link show" \
                " | cut -d ':' -f 2 | grep -v 'lo:'" % ns)
            if out:
                for intf in out.splitlines():
                    self.sim._run("ip netns exec %s ip link set netns 1 dev %s" % \
                        (ns, intf))
            self.sim._run("ip netns del %s" % ns)

        # now create the namespace and add tap interfaces.  If
        # tap interfaces haven't been created yet, defer adding
        # to namespace (they'll be added when created).

        out, err = self.sim._run("ip netns add %s" % ns)
        if err: raise SimpNodeError("%s: Error create namespace %s: %s" % \
            (self.sim.sim_name, ns, err))

        for intf in self.intfs:
            nbr = intf.opposite.node
            if nbr.started:
                tap_name = "%s-%s-%s" % (self.sim.sim_name,
                    self.name, intf.name)

                # might have to wait a bit for nbr interface to show up

                for i in range(10):
                    out, err = self.sim._run("ip link show %s" % tap_name)
                    if not err: break
                    sleep(0.1)
                if i == 9:
                    raise SimpNodeError("%s: Interface %s not ready to add " \
                        "to namespace %s" % \
                        (self.sim.sim_name, tap_name, ns))

                out, err = self.sim._run("ip link set netns %s dev %s" % \
                    (ns, tap_name))
                if err: raise SimpNodeError("%s: Error adding interface %s " \
                    "to namespace %s: %s" % \
                    (self.sim.sim_name, tap_name, ns, err))
                our, err = self.sim._run("ip netns exec %s " \
                    "ip link set name %s dev %s" % \
                    (ns, intf.name, tap_name))
                if err: raise SimpNodeError("%s: Error create namespace %s: %s" % \
                    (self.sim.sim_name, ns, err))

        self.started = time()

    def stop(self):

        if not self.started:
            return

        logger.info("%s: stopping node '%s'..." % (self.sim.sim_name, self.name))

        ns = self.ns()

        for intf in self.intfs:
            nbr = intf.opposite.node
            tap_name = "%s-%s-%s" % (self.sim.sim_name,
                self.name, intf.name)
            self.sim._run("ip netns exec %s ip link set name %s dev %s" % \
                (ns, tap_name, intf.name))
            self.sim._run("ip netns exec ip link set netns 1 dev %s" % \
                tap_name)

        self.sim._run("ip netns del %s" % ns)

        self.started = None

class SimpNodeDynamips(SimpNode): pass

class SimpSimError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)
        logger.critical(message)

class SimpSim(object):

    def __init__(self, sim_name, dot_data, options, image_dir):

        self.created = time()
        self.sim_name = sim_name
        self.dot_data = dot_data
        self.options = options
        self.image_dir = image_dir
        self.sim_image_dir = None
        self.nodes = {}
        self.parsed_options = {}

        self._parse_options()
        self._parse_dot()
        self._checkup()
        self._create_images_mount()
        self._assign_ports()

        logger.info("%s: sim created" % self.sim_name)

    def _run(self, cmd, wait=True, out=subprocess.PIPE):

        logger.debug("%s: run: %s" % (self.sim_name, cmd))
        p = subprocess.Popen(cmd, shell=True,
            stdout=out, stderr=subprocess.STDOUT)
        if wait:
            return p.communicate()

    def _parse_options(self):

        for o in self.options:

            try:
                node_name, option, value = o.split(':', 2)
            except:
                raise SimpSimError("%s: malformed option '%s'" % \
                    (self.sim_name, o))

            if option not in ["mem", "type", "base", "map", "rocker", "bin"]:
                raise SimpSimError("%s: option '%s' bad option name '%s'" % \
                    (self.sim_name, o, option))

            self.parsed_options.setdefault(node_name, {})[option] = value

        for n, p in self.parsed_options.items():
            logger.debug("parsed options: %s: %s" % (n, p))

    def _node_type(self, node_name):

        options = self.parsed_options.get(node_name)
        if options:
            return options.get("type", "qemu-x86_64")
        else:
            return "qemu-x86_64"

    def _new_node(self, node_name):

        node_type = self._node_type(node_name)
        options = self.parsed_options.get(node_name, {})

        if node_type == "qemu-x86_64":
            return SimpNodeQemu(self, node_name, node_type, options)
        elif node_type == "dynamips":
            return SimpNodeDynamips(self, node_name, node_type, options)
        elif node_type == "physical":
            return SimpNodePhysical(self, node_name, node_type, options)
        elif node_type == "namespace":
            return SimpNodeNameSpace(self, node_name, node_type, options)
        else:
            raise SimpSimError("%s: node %s: unknown type: %s" % \
                (self.sim_name, node_name, node_type))

    def _parse_dot(self):

        if self.sim_name == "base":
            node_name = "base"
            node = self._new_node(node_name)
            node.number = 0
            self.nodes[node_name] = node
            return

        try:
            self.graph = pydot.graph_from_dot_data(self.dot_data)

        except Exception as error:
            raise SimpSimError("%s: error parsing .dot data: %s" % \
                (self.sim_name, str(error)))

        edges = self.graph.get_edges()

        for edge in edges:
            src = edge.get_source()
            dst = edge.get_destination()

            src_node_name, src_intf_name = src.split(':')
            src_node_name = src_node_name.replace('"', '')
            src_node = self.nodes.setdefault(src_node_name,
                self._new_node(src_node_name))
            src_intf = SimpIntf(src_intf_name, src_node)
            self.nodes[src_node_name].intfs.append(src_intf)

            dst_node_name, dst_intf_name = dst.split(':')
            dst_node_name = dst_node_name.replace('"', '')
            dst_node = self.nodes.setdefault(dst_node_name,
                self._new_node(dst_node_name))
            dst_intf = SimpIntf(dst_intf_name, dst_node)
            self.nodes[dst_node_name].intfs.append(dst_intf)

            src_intf.opposite = dst_intf
            dst_intf.opposite = src_intf

        for i, node in enumerate(self.nodes.values()):
            node.number = i
            node.intfs.sort(key=lambda intf: intf.name)

        for node in self.nodes.values():
            for i, intf in enumerate(node.intfs):
                intf.mac = node.swp_mac(i)

        logger.info("%s: parsed .dot data: %d nodes, %d interfaces" % \
            (self.sim_name, len(self.nodes),
            sum([len(node.intfs) for node in self.nodes.values()])))

    def _checkup(self):

        # namespaces can't be connected to each other

        for node in self.nodes.values():
            for intf in node.intfs:
                nbr = intf.opposite.node
                if node.node_type == nbr.node_type and \
                    node.node_type == "namespace":
                    raise SimpSimError("%s: node %s and neighbor %s " \
                        "can't both be namespaces" % \
                        (self.sim_name, node.name, nbr.name))

        # bad node references in options?

        existing = set([node.name for node in self.nodes.values()])
        parsed = set(self.parsed_options.keys())
        if not parsed.issubset(existing):
            raise SimpSimError("%s: options reference non-existing nodes: %s" \
                (self.sim_name, parsed.difference(existing)))

    def _create_images_mount(self):

        if self.sim_name == "base":
            self.sim_image_dir = config.root_image_dir + '/'
            return

        self.sim_image_dir = self.image_dir + '/' + self.sim_name
        if os.path.exists(self.sim_image_dir):
            self._run("umount %s" % self.sim_image_dir)
            self._run("rm -rf %s" % self.sim_image_dir)
        out, err = self._run("mkdir -p %s" % self.sim_image_dir)
        if err: raise SimpSimError("%s: %s" % (self.sim_name, err))

        # give 200M for each node's image file
        tmpfs_size = 200 * len(self.nodes)
        cmd = "mount -t tmpfs -o size=%dM %s %s" % \
            (tmpfs_size, self.sim_image_dir, self.sim_image_dir)
        out, err = self._run(cmd)
        if err: raise SimpSimError("%s: %s" % (self.sim_name, err))

        logger.info("%s: created disk image storage" % self.sim_name)

    def _destroy_images_mount(self):

        if self.sim_name == "base": return
        if not self.sim_image_dir: return

        for i in range(10):
            out, err = self._run("umount %s" % self.sim_image_dir)
            if not err: break
            sleep(0.1)

        if i == 9:
            logger.error("%s: umount %s failed" % \
                (self.sim_name, self.sim_image_dir))

        out, err = self._run("rm -rf %s" % self.sim_image_dir)

        for node in self.nodes.values():
            node.base_img = None

        logger.info("%s: destroyed disk images" % self.sim_name)

    def _assign_ports(self):

        def get_locked_port():
            while True:
                assert avail_ports, "Out of ports!"
                port = avail_ports.pop(0)
                try:
                    lf = lockfile.FileLock(config.portlocker_dir + str(port))
                    lf.acquire(.01)
                    # This means that all locks must be broken, not released.
                    # lockfile doesn't do good cleanup on its own.
                    os.unlink(lf.unique_name)
                except lockfile.LockError:
                    continue
                return port

        # ports in use by any application
        cmd = "netstat -a -n | grep '^udp\|^tcp' | cut -c21-44 | rev | " \
              "cut -d ':' -f1 | rev | cut -d ' ' -f1 | sort | uniq"
        out, err = self._run(cmd)
        used_ports = [int(port) for port in out.splitlines()]

        # ports previously locked (reserved) by sim
        pname = lambda fname: int(fname.split('.')[0])
        pfnames = os.listdir(config.portlocker_dir)
        used_ports += [pname(fname) for fname in pfnames if '.lock' in fname]

        avail_ports = range(1025, 2**16)
        avail_ports = sorted(set(avail_ports) - set(used_ports))

        for node in self.nodes.values():
            node.ssh_port = get_locked_port()
            node.console_port = get_locked_port()
            node.monitor_port = get_locked_port()
            for intf in node.intfs:
                intf.port = get_locked_port()

    def _clear_ports(self):

        def release_port(port):
            lf = lockfile.FileLock(config.portlocker_dir + str(port))
            lf.break_lock()

        for node in self.nodes.values():
            release_port(node.ssh_port)
            release_port(node.console_port)
            release_port(node.monitor_port)
            for intf in node.intfs:
                release_port(intf.port)

    def destroy(self):

        self._clear_ports()
        self._destroy_images_mount()
        logger.info("%s: sim destroyed" % self.sim_name)

    def get_status(self):

        out = ""
        out += "Name = %s\n" % self.sim_name
        out += "Created = %s\n" % strftime("%x %X", localtime(self.created))
        out += "Nodes = %d\n" % len(self.nodes)
        return out

class SimpClient(object):

    def __init__(self, sock):
        self.sock = sock
        self.buf = ""

class SimpServer(socket.socket):

    def __init__(self, port):

        logger.info("hello - server starting")

        self.port = port
        self.clients = {}
        self.sims = {}

        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind(("", port))
        self.listen(5)

        self.epoll = select.epoll()
        self.epoll.register(self.fileno(), select.EPOLLIN)

        self.image_dir = config.root_image_dir + '-' + str(port)
        self._prepare_lock_dir()

    def _prepare_lock_dir(self):

        if not os.path.exists(config.portlocker_dir):
            os.mkdir(config.portlocker_dir)
            os.chmod(config.portlocker_dir, 0777)

    def client_close(self, fileno):

        self.epoll.unregister(fileno)
        self.clients[fileno].sock.close()
        del self.clients[fileno]

    def kill_all(self):

        sims = self.sims.values()
        for sim in sims:
            self.destroy([sim.sim_name])

    def get_sim(self, sim_name):

        if sim_name not in self.sims:
            raise Exception("Sim '%s' does not exist" % sim_name)
        return self.sims[sim_name]

    def get_node(self, sim, node_name):

        if node_name not in sim.nodes:
            raise Exception("Node '%s' not in sim '%s'" % \
                (node_name, sim.sim_name))
        return sim.nodes[node_name]

    def get_intf(self, sim, node_name, intf_name):

        if node_name not in sim.nodes:
            raise Exception("Node '%s' not in sim '%s'" % \
                (node_name, sim.sim_name))
        node = sim.nodes[node_name]
        for intf in node.intfs:
            if intf.name == intf_name:
                return intf
        return None

    def create(self, args):

        sim_name, dot_data, options = args
        if sim_name in self.sims:
            raise Exception("Sim '%s' already exists" % sim_name)

        self.sims[sim_name] = \
            SimpSim(sim_name, dot_data, options, self.image_dir)
        return (sim_name, "")

    def create_image(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        node.create_image()
        return ("", "")

    def destroy(self, args):

        sim_name = args[0]
        sim = self.get_sim(sim_name)
        for node in sim.nodes.values():
            node.stop()
        sim.destroy()
        del self.sims[sim_name]
        return ("", "")

    def attach(self, args):

        sim_name = args[0]
        sim = self.get_sim(sim_name)
        return (sim_name, "")

    def start(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)

#        running = len([n for s in self.sims.values()
#            for n in s.nodes if s.running])
#        potential = running + len(sim.nodes)
#
#        if potential > 400:
#            return ("", "Sorry, too many simulation nodes running")
#        elif running > 200:
#            sim.start(node)
#            return ("WARNING: greater than 200 simulation nodes running", "")
#        else:
#            sim.start(node)
#            return ("", "")

        node.start()
        return ("", "")

    def stop(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        node.stop()
        return ("", "")

    def link_ctrl(self, args):

        return ("", "not implemented :(")

    def get_sim_list(self, args):

        return (self.sims.keys(), "")

    def get_node_names(self, args):

        sim_name = args[0]
        sim = self.get_sim(sim_name)
        return ([node_name for node_name in sim.nodes], "")

    def get_intf_names(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        return ([intf.name for intf in node.intfs], "")

    def get_link_port(self, args):

        return ("", "not implemented :(")

    def get_ssh_port(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        if not node.running():
            return ("", "Node '%s' in sim '%s' not running" % \
                (node_name, sim_name))
        return (node.ssh_port, "")

    def get_console_port(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        if not node.running():
            return ("", "Node '%s' in sim '%s' not running" % \
                (node_name, sim_name))
        return (node.console_port, "")

    def get_monitor_port(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        if not node.running():
            return ("", "Node '%s' in sim '%s' not running" % \
                (node_name, sim_name))
        return (node.monitor_port, "")

    def get_status(self, args):

        sim_name = args[0]
        sim = self.get_sim(sim_name)
        return (sim.get_status(), "")

    def get_node_status(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        return (node.get_status(), "")

    def get_intf_status(self, args):

        sim_name, node_name, intf_name = args
        sim = self.get_sim(sim_name)
        intf = self.get_intf(sim, node_name, intf_name)
        return (intf.get_status(), "")

    def get_link_status(self, args):

        return ("", "not implemented :(")

    def get_node_type(self, args):

        sim_name, node_name = args
        sim = self.get_sim(sim_name)
        node = self.get_node(sim, node_name)
        return (node.node_type, "")

    def process_args(self, args):

        cmds = {
            "create": self.create,
            "create_image": self.create_image,
            "destroy": self.destroy,
            "attach": self.attach,
            "start": self.start,
            "stop": self.stop,
            "link_ctrl": self.link_ctrl,
            "get_sim_list": self.get_sim_list,
            "get_node_names": self.get_node_names,
            "get_intf_names": self.get_intf_names,
            "get_link_port": self.get_link_port,
            "get_ssh_port": self.get_ssh_port,
            "get_console_port": self.get_console_port,
            "get_monitor_port": self.get_monitor_port,
            "get_status": self.get_status,
            "get_node_status": self.get_node_status,
            "get_intf_status": self.get_intf_status,
            "get_link_status": self.get_link_status,
            "get_node_type": self.get_node_type,
        }

        cmd = args[0]
        if cmd not in cmds:
            return ("", "Unknown command: %s" % cmd)

        try:
            return cmds[cmd](args[1:])
        except Exception as error:
            logger.debug(format_exc())
            return ("", str(error))

    def process_client(self, client):

        #
        # When client signals read ready (EPOLLIN), we expect to
        # read two things from client: 
        #
        #   4 bytes encoding integer N,
        #   N bytes of pickled cmd payload
        #
        # We'll read as much as we can with one read, but may need
        # need to come back and read more until N and full payload
        # have been read.  Use client.buf to accumulate the
        # read data.  Once N and payload have been read fully, 
        # unpickle the payload, process the msg, and clear
        # client.buf for next msg.
        #

        buf = client.sock.recv(2048)
        if not buf:   # EOF
            return False

        client.buf += buf

        if len(client.buf) < 4:
            return True

        try:
            N = int(struct.unpack('I', client.buf[0:4])[0])
        except ValueError:
            return False

        if len(client.buf) < N + 4:
            return True

        try:
            args = pickle.loads(client.buf[4:N+4])
        except:
            return False
        finally:
            client.buf = ""

        ret = self.process_args(args)

        pret = pickle.dumps(ret, pickle.HIGHEST_PROTOCOL)

        try:
            client.sock.sendall(struct.pack('I', len(pret)))
            client.sock.sendall(pret)
        except socket.error:
            return False

        return True

    def process(self):

        events = self.epoll.poll()

        for fileno, event in events:

            if fileno == self.fileno():

                client_sock, address = self.accept()
                self.epoll.register(client_sock.fileno(), select.EPOLLIN)
                self.clients[client_sock.fileno()] = \
                    SimpClient(client_sock)

            elif event & select.EPOLLIN:

                client = self.clients[fileno]
                if not self.process_client(client):
                    self.client_close(fileno)

def quit_gracefully(*args):
    global done
    logger.info("goodbye - server exiting")
    done = True

signal.signal(signal.SIGINT, quit_gracefully)
signal.signal(signal.SIGTERM, quit_gracefully)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Simp Server')
    parser.add_argument('-l', '--log', help='initial log level', \
        default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('-p', '--port', help='server listen port', type=int, default=6667)
    args = parser.parse_args()

    if os.getuid():
        print "Sorry, need to run with admin privs"
        sys.exit(1)

    logging.basicConfig(level=getattr(logging, args.log.upper()),
         filename='%s-%d.log' % (config.log_base, args.port),
         format='%(asctime)s %(levelname)s: %(message)s')

    s = None
    try:
        s = SimpServer(args.port)
        while not done:
            s.process()

    except socket.error, (errno, string):
        logger.error("Socket err[%d]: %s" % (errno, string))

    except Exception as error:
        logger.error(str(error))

    if s:
        s.kill_all()
    sys.exit(0)
