import argparse
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class CustomTopo(Topo):
    def build(self, num_hosts, delay, loss):
        s1 = self.addSwitch('s1')

        server = self.addHost('server', ip='10.0.0.100/8')
        self.addLink(server, s1, cls=TCLink, loss=loss, delay=delay)

        for i in range(1, num_hosts + 1):
            h_name = f'h{i}'
            h_ip = f'10.0.0.{i}'
            h = self.addHost(h_name, ip=h_ip)
            self.addLink(h, s1, cls=TCLink, loss=loss, delay=delay)


def run(num_hosts, delay, loss):
    topo = CustomTopo(num_hosts=num_hosts, delay=delay, loss=loss)

    net = Mininet(topo=topo, controller=OVSController, link=TCLink)

    net.start()

    info('*** Red Iniciada. El servidor es 10.0.0.100\n')
    info(f'*** Se crearon {num_hosts} clientes (h1 a h{num_hosts})\n')
    info(f'*** Todos los enlaces tienen un delay de {delay} y {loss}% de pérdida\n')

    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    parser = argparse.ArgumentParser(description="Topología parametrizada de Mininet")
    parser.add_argument('--hosts', type=int, default=4, help='Cantidad de hosts clientes (por defecto: 4)')
    parser.add_argument('--delay', type=str, default='75ms', help='Delay de los enlaces (por defecto: 75ms)')
    parser.add_argument('--loss', type=float, default=5.0, help='Porcentaje de pérdida de paquetes (por defecto: 5)')

    args = parser.parse_args()

    run(args.hosts, args.delay, args.loss)