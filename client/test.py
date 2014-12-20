#!/usr/bin/env python

from simp_client import SimpClient
from argparse import ArgumentParser
from traceback import print_stack
import sys
import time
import subprocess

parser = ArgumentParser(description="Linux Simulator Tester")
parser.add_argument('-H', '--host', help='name of simulation host', default='localhost')
parser.add_argument('-p', '--port', help='port to connect to simulation host', type=int, default=6667)
parser.add_argument('-t', '--test', help='test to run (default all)')
args = parser.parse_args()

s2x2_dot = """
graph G {
	graph [hostidtype="hostname", version="1:0", date="04/12/2013"];
	edge [dir=none, notify="log"];
	bottom0:swp1 -- top0:swp1;
	bottom0:swp2 -- top1:swp1;
	bottom1:swp1 -- top0:swp2;
	bottom1:swp2 -- top1:swp2;
}
"""

s2x2_broken_dot = """
graph G {
	graph [hostidtype="hostname", version="1:0", date="04/12/2013"];
	edge [dir=none, notify="log"];
	bottom0:swp1 ** top0:swp1;
	bottom0:swp2 -- top1:swp1;
	bottom1:swp1 -- top0:swp2;
	bottom1:swp2 -- top1:swp2;
}
"""

def run(node, cmd):

    rsa = "/usr/share/simp/simp_rsa"
    port = sim.get_ssh_port(node)

    ssh_cmd = "ssh -q -o StrictHostKeyChecking=no " \
        "-o UserKnownHostsFile=/dev/null " \
        "-i %s -p %d simp@%s %s" % \
        (rsa, port, args.host, cmd)

    p = subprocess.Popen(ssh_cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    returncode = p.returncode

    if returncode != 0:
        print "******* FAILURE **********"
        print
        print "Output:"
        print out
        print
        print "Traceback:"
        print print_stack()
        print
        raise Exception(err)

    return out

def test_base():

    print "testing base..."

    sim.create("base", dot_data=None)

    try:
        nodes = sim.get_node_names()
        for node in nodes:
            sim.create_image(node)
            sim.start(node)

        ready = False
        for i in range(30):
            status = sim.get_node_status("base")
            if "SSH? = Yes" in status:
                ready = True
                break
            time.sleep(1)

        assert ready, "Node base not SSH ready"

        for node in nodes:
            sim.stop(node)

    finally:
        sim.destroy()

def test_bugus_calls():

    print "testing bogus calls..."

    try:
        sim.attach("foo")
        raise Exception("attach() should have failed")
    except:
        pass

    try:
        sim.start("goober")
        raise Exception("start() should have failed")
    except:
        pass

    try:
        sim.stop("goober")
        raise Exception("stop() should have failed")
    except:
        pass

    try:
        sim.destroy()
        raise Exception("destroy() should have failed")
    except:
        pass

    try:
        sim.get_ssh_port("bar")
        raise Exception("get_ssh_port() should have failed")
    except:
        pass

    try:
        sim.get_console_port("bar")
        raise Exception("get_console_port() should have failed")
    except:
        pass

    try:
        sim.get_monitor_port("bar")
        raise Exception("get_monitor_port() should have failed")
    except:
        pass

    try:
        file_data = sim.get_node_names()
        raise Exception("get_node_names() should have failed")
    except:
        pass

    try:
        file_data = sim.get_intf_names("foo")
        raise Exception("get_int_names() should have failed")
    except:
        pass

def test_create_destroy():

    print "testing create/destroy..."

    sim.create("s2x2", s2x2_dot)

    try:
        try:
            sim.create("s2x2", s2x2_dot)
            raise Exception("double create should have failed")
        except:
            pass

        sims = sim.get_sim_list()
        assert "s2x2" in sims, "s2x2 not in sims list"

    finally:
        sim.destroy()

    sim.create("s2x2", s2x2_dot)
    sim.destroy()

    try:
        sim.destroy()
        raise Exception("double destroy should have failed")
    except:
        pass

    try:
        sim.create("s2x2", s2x2_broken_dot)
        raise Exception("broken s2x2 dot create should have failed")
    except:
        pass

def test_start_stop():

    print "testing start/stop..."

    sim.create("s2x2", s2x2_dot)

    try:
        nodes = sim.get_node_names()
        for node in nodes:
            sim.create_image(node)
            sim.start(node)

        try:
            for node in nodes:
                sim.start(node)
            raise Exception("double start should have failed")
        except:
            pass

        for node in nodes:
            sim.stop(node)

        try:
            for node in nodes:
                sim.stop(node)
            raise Exception("double stop should have failed")
        except:
            pass

        for node in nodes:
            sim.start(node)
            sim.stop(node)
            sim.start(node)

    finally:
        sim.destroy()

def test_ssh():

    print "testing ssh..."

    sim.create("s2x2", s2x2_dot)

    try:
        nodes = sim.get_node_names()
        for node in nodes:
            sim.create_image(node)
            sim.start(node)

        time.sleep(30)

        for node in nodes:
            status = sim.get_node_status(node)
            assert "SSH? = Yes" in status, "Node %s not SSH ready" % node

        for node in nodes:
            sim.stop(node)

    finally:
        sim.destroy()

def test_node_to_node():

    print "testing node to node connectivity..."

    sim.create("s2x2", s2x2_dot)

    try:

        nodes = sim.get_node_names()

        for node in nodes:
            sim.create_image(node)
            sim.start(node)

        for i in range(10):
            ready = True
            for node in nodes:
                status = sim.get_node_status(node)
                if "SSH? = No" in status:
                    ready = False
                    break
            if not ready:
                time.sleep(5)

        assert ready, "Node %s not SSH ready" % node

        run("top0", "sudo ifconfig swp1 11.0.0.2/30")
        run("bottom0", "sudo ifconfig swp1 11.0.0.1/30")
        run("bottom0", "ping -c 10 11.0.0.2")

        for node in nodes:
            sim.stop(node)

    finally:
        sim.destroy()

def test_many_sims():

    print "testing many sims..."

    names = ["s2x2_%d" % i for i in range(25)]

    try:
        for name in names:
            sim.create(name, s2x2_dot)
            nodes = sim.get_node_names()
            for node in nodes:
                sim.create_image(node)
                sim.start(node)

        passed = True
        for name in names:
            sim.attach(name)
            print "  waiting for sim %s to respond. ." % name,
            for i in range(120):
                status = sim.get_node_status("top0")
                if "SSH? = Yes" in status: break
                time.sleep(1)
                print ".",
            print
            if i == 119:
                print "SSH ready for sim %s node top0 failed" % name
                passed = False 

        assert passed, "One or more sim nodes failed to come up"

        for name in names:
            sim.attach(name)
            sim.stop(node)

    finally:
        for name in names:
            sim.attach(name)
            sim.destroy()

try:

    try:
        sim = SimpClient(args.host, args.port)
    except Exception as error:
        raise Exception("Is test_server running?  Got: %s" % str(error))

    tests = {
        "test_bogus_calls": test_bugus_calls,
        "test_base": test_base,
        "test_create_destroy": test_create_destroy,
        "test_start_stop": test_start_stop,
        "test_ssh": test_ssh,
        "test_node_to_node": test_node_to_node,
        "test_many_sims": test_many_sims,
    }

    if args.test:
        if args.test in tests:
            tests[args.test]()
    else:
        for test in tests.values():
            test()

except KeyboardInterrupt:
    exit(1)

except Exception as error:
    print str(error)
    exit(1)
