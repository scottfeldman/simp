#!/usr/bin/env python

import simp_server
import logging

logging.basicConfig(level=logging.DEBUG,
     format='%(asctime)s %(levelname)s: %(message)s')

try:
    s = simp_server.SimpServer(7776)
    s.process()

except KeyboardInterrupt:
    pass

except Exception as error:
    print str(error)

s.kill_all()
