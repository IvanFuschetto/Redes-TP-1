from mininet.net import Mininet
from mininet.node import OVSController
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class CustomTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        server = self.addHost('server', ip='10.0.0.100/8')
        self.addLink(server, s1, cls=TCLink,delay='75ms')

        h1 = self.addHost('h1', ip='10.0.0.1')
        h2 = self.addHost('h2', ip='10.0.0.2')
        h3 = self.addHost('h3', ip='10.0.0.3')
        h4 = self.addHost('h4', ip='10.0.0.4')

        self.addLink(h1, s1, cls=TCLink, loss=5, delay='75ms')
        self.addLink(h2, s1, cls=TCLink, loss=5, delay='75ms')
        self.addLink(h3, s1, cls=TCLink, loss=5, delay='75ms')
        self.addLink(h4, s1, cls=TCLink, loss=5, delay='75ms')


def run():
    topo = CustomTopo()

    net = Mininet(topo=topo, controller=OVSController, link=TCLink)

    net.start()

    info('*** Red Iniciada. El servidor es 10.0.0.100\n')
    info(
        '*** Los clientes h1 (10.0.0.1), h2 (10.0.0.2),'
        'h3 (10.0.0.3) y h4 (10.0.0.4) tienen 5% de pérdida\n'
        )

    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()