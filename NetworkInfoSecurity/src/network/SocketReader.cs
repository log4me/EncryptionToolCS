using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NetworkInfoSecurity.network;
using NetworkInfoSecurity;
using System.Net.Sockets;
namespace NetworkInfoSecurity.network
{
    
    class SocketReader : Thread
    {
        private Received_CallBack after_Received = null;
        private Socket in_socket = null;
        private byte[] in_data = null;
        private long BUF_SIXE = 102400;
        private DataDecode decoder = null;
        private MainWindow mainWindow;
        private Error_handle errorHandle;
        public SocketReader(Received_CallBack after_Received, Socket socket, MainWindow mainWindow, Error_handle errorHandle,DataDecode decoder = null)
        {
            this.after_Received = after_Received;
            this.in_socket = socket;
            this.in_data = new byte[this.BUF_SIXE];
            if (decoder != null)
            {
                this.decoder = decoder;
            }
            this.mainWindow = mainWindow;
            this.errorHandle = errorHandle;
        }
        public override void run()
        {
            
            int recv_len = this.in_socket.Receive(this.in_data);
            Dictionary<string, string> decode_info = new Dictionary<string, string>();
            decode_info.Add("SYM_ENC_METHOD", this.mainWindow.GetSYM_METHOD());
            decode_info.Add("HASH_FUNCTION", this.mainWindow.GetHash_Function());
            decode_info.Add("B_RSA_PK_PATH", this.mainWindow.Get_B_RSA_PK_PATH());
            decode_info.Add("A_RSA_UK_PATH", this.mainWindow.Get_A_RSA_UK_PATH());
            byte[] read_data = new byte[recv_len];
            Dictionary<string, byte[]> decode_res=null;
            Array.ConstrainedCopy(in_data, 0, read_data, 0, recv_len);
            try
            {
                decode_res = this.decoder(read_data, decode_info);
                after_Received(decode_res);
            }
            catch (Exception e)
            {
                this.errorHandle(e.Message);
            }
            
        }
    }
}
