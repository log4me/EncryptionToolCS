using NetworkInfoSecurity.crypt;
using NetworkInfoSecurity.network;
using System;
using System.Windows.Forms;
using NetworkInfoSecurity.config;
namespace NetworkInfoSecurity
{
    static class Program
    {
        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            MainWindow mainWindow = new MainWindow();
            NetListener bListener = new NetListener(mainWindow, mainWindow.errorHandle, ip:Config.IP, port:Config.PORT, decoder:Crypt.decode);
            bListener.start();
            Application.Run(mainWindow);
        }
    }
}
