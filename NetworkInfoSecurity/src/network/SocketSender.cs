using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using NetworkInfoSecurity.network;
namespace NetworkInfoSecurity.network
{
    class SocketSender : Thread
    {
        private byte[] data = null;
        private string ip = "127.0.0.1";
        private int port = 6666;
        private DataEncode encoder = null;
        private Dictionary<string, string> encode_info;
        private Error_handle error_handler;
        public SocketSender(byte[] data, Dictionary<string, string> encode_info, Error_handle error_handler,string ip="127.0.0.1", int port=6666, DataEncode encoder=null)
        {
            this.data = data;
            this.ip = ip;
            this.port = port;
            if (encoder != null)
            {
                this.encoder = encoder;
            }
            this.encode_info = encode_info;
            this.error_handler = error_handler;
        }
        public override void run()
        {
            try
            {
                this.data = this.encoder(this.data, encode_info);
            }
            catch (ArgumentException)
            {
                this.error_handler("AES/DES密钥大小不符合要求，请重新选择密钥.");
                return;
            }
            catch (Exception e)
            {
                this.error_handler(e.Message);
                return;
            }
            IPAddress server_address = IPAddress.Parse(this.ip);
            IPEndPoint ip_port = new IPEndPoint(server_address, this.port);
            Socket server_socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            server_socket.Connect(ip_port);
            server_socket.Send(this.data);
        }
    }
}
