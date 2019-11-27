using System;
using System.Net.Sockets;
using System.Net;
namespace NetworkInfoSecurity.network
{
    class NetListener : Thread
    {
        private String ip="127.0.0.1";
        private int port=6666;
        Socket listen_socket = null;
        private MainWindow mainWindow = null;
        private DataDecode decoder = null;
        private Error_handle error_handler;
        public NetListener(MainWindow mainWindow, Error_handle error_handler,String ip="127.0.0.1", int port=6666, DataDecode decoder=null)
        {
            this.ip = ip;
            this.port = port;
            this.mainWindow = mainWindow;
            if (decoder != null)
            {
                this.decoder = decoder;
            }
            this.error_handler = error_handler;
            listen_socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPAddress ip_address = IPAddress.Parse(this.ip);
            IPEndPoint ip_port = new IPEndPoint(ip_address, this.port);
            listen_socket.Bind(ip_port);
        }
        public override void run()
        {
            while (true)
            {
                this.listen_socket.Listen(1);
                Socket conn = this.listen_socket.Accept();
                new SocketReader(new Received_CallBack(this.mainWindow.received_CallBack), conn, this.mainWindow, this.error_handler, decoder:this.decoder).start();
            }
        }
    }
}

