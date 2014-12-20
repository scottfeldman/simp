from distutils.core import setup

setup(
    name="simp-server",
    version="0.1",
    description = "Simple Network Simulator Server",
    author='Scott Feldman',
    author_email='sfeldma@gmail.com',
    url='gmail.com',
    py_modules=['simp_server', 'config'],
    data_files=[('/etc/init.d/', ['init.d/simp_server']),
                ('/usr/share/simp/', ['tap-ifup'])]
)
