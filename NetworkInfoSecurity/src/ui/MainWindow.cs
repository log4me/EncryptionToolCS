using NetworkInfoSecurity.crypt;
using NetworkInfoSecurity.config;
using NetworkInfoSecurity.network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;
namespace NetworkInfoSecurity
{
    // 消息解码完成后的回调函数
    public delegate void Received_CallBack(Dictionary<string, byte[]> decode_res);
    // 跨线程设置textBox文本
    public delegate void SetText(TextBox textBox, String text);
    // 数据编码
    public delegate byte[] DataEncode(byte[] data, Dictionary<String, String> encode_info);
    // 数据解码
    public delegate Dictionary<String, byte[]> DataDecode(byte[] data, Dictionary<String, String> decode_info);
    // 错误处理
    public delegate void Error_handle(string error_msg);
    public partial class MainWindow : Form
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        // Properties
        // Common Properties of Abox and Bbox
        private String SYM_METHOD="DES";

        private String HASH_FUNCTION="MD5";
        // ABox properties
        private String ABox_A_RSA_PRI_PATH;
        private String ABox_B_RSA_PUB_PATH;
        private String ABox_DES_AES_KEY_PATH;
        // BBox Properties
        private String BBox_A_RSA_PUB_PATH;
        private String BBox_B_RSA_PRI_PATH;

        public String GetSYM_METHOD()
        {
            return this.SYM_METHOD;
        }
        public String GetHash_Function()
        {
            return this.HASH_FUNCTION;
        }
        public String Get_A_RSA_UK_PATH()
        {
            return BBox_A_RSA_PUB_PATH;
        }
        public String Get_B_RSA_PK_PATH()
        {
            return BBox_B_RSA_PRI_PATH;
        }

        private void Action_Aes_Key_Generate_Click(object sender, EventArgs e)
        {
            byte[] aesKey = new byte[Config.AES_KEY_LENGTH];
            RNGCryptoServiceProvider csp = new RNGCryptoServiceProvider();
            csp.GetBytes(aesKey);
            SaveFileDialog sfd = new SaveFileDialog();
            sfd.InitialDirectory = "~";
            sfd.RestoreDirectory = true;
            sfd.CheckPathExists = true;
            sfd.CheckFileExists = false;
            if (sfd.ShowDialog() == DialogResult.OK && sfd.FileName.Length > 0)
            {
                try
                {
                    BinaryWriter bw = new BinaryWriter(new FileStream(sfd.FileName, FileMode.Create));
                    bw.Write(aesKey);
                    bw.Close();
                }
                catch (IOException ex)
                {
                    MessageBox.Show(this, "文件创建失败。" + ex.Message);
                }
            }
        }

        private void Action_Des_Key_Generate_Click(object sender, EventArgs e)
        {
            byte[] desKey = new byte[64 / 8];
            RNGCryptoServiceProvider csp = new RNGCryptoServiceProvider();
            csp.GetBytes(desKey);
            SaveFileDialog sfd = new SaveFileDialog();
            sfd.InitialDirectory = "~";
            sfd.RestoreDirectory = true;
            sfd.CheckPathExists = true;
            sfd.CheckFileExists = false;
            if (sfd.ShowDialog() == DialogResult.OK && sfd.FileName.Length > 0)
            {
                try
                {
                    BinaryWriter bw = new BinaryWriter(new FileStream(sfd.FileName, FileMode.Create));
                    bw.Write(desKey);
                    bw.Close();
                }
                catch (IOException ex)
                {
                    MessageBox.Show("文件创建失败。" + ex.Message);
                }
            }
        }
        private void Action_Rsa_Keypair_Generate_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog path = new FolderBrowserDialog();
            if (path.ShowDialog() == DialogResult.OK)
            {
                string folder_path = path.SelectedPath;
                RsaKeyPair keyPair = RSAGeneratorKey.generatorKey(Config.RSA_KEY_LENGTH);
                keyPair.getPublicKey().saveToFile(Path.Combine(folder_path, "uk"));
                keyPair.getPrivateKey().saveToFile(Path.Combine(folder_path, "pk"));
            }
        }

        // Abox event
        private void MD5_SHA_RadioButton_CheckChanged(object sender, EventArgs e)
        {
            if (sender == this.MD5_RadioButton)
            {
                this.HASH_FUNCTION = "MD5";
            }
            else if (sender == this.SHA_RadioButton)
            {
                this.HASH_FUNCTION = "SHA";
            }
            else
            {
                //Do Nothing
            }
        }

        private void DES_AES_RadioButton_CheckChanged(object sender, EventArgs e)
        {
            if (sender == this.DES_RadioButton)
            {
                this.SYM_METHOD = "DES";
                this.ABox_DES_AES_Label.Text = "DES密钥:";
                this.DES_AES_TextBox.Text = "";
                this.ABox_DES_AES_KEY_PATH = "";
            }
            else if (sender == this.AES_RadioButton)
            {
                this.SYM_METHOD = "AES";
                this.ABox_DES_AES_Label.Text = "AES密钥:";
                this.DES_AES_TextBox.Text = "";
                this.ABox_DES_AES_KEY_PATH = "";
            }
            else
            {
                //Do Nothing
            }
        }


        private void A_RSA_PRI_TextBox_Validated(object sender, EventArgs e)
        {
            String path = this.A_RSA_PRI_TextBox.Text;
            if (!File.Exists(path))
            {
                MessageBox.Show(this, "请选择正确的密钥文件", "密钥文件不存在");
            }
            else
            {
                this.ABox_A_RSA_PRI_PATH = path;
            }
        }

        private void B_RSA_PUB_TextBox_Validated(object sender, EventArgs e)
        {
            String path = this.B_RSA_PUB_TextBox.Text;
            if (!File.Exists(path))
            {
                MessageBox.Show("请选择正确的密钥文件", "密钥文件不存在");
            }
            else
            {
                this.ABox_B_RSA_PUB_PATH = path;
            }
        }

        private void DES_AES_TextBox_Validated(object sender, EventArgs e)
        {
            String path = this.DES_AES_TextBox.Text;
            if (!File.Exists(path))
            {
                MessageBox.Show("请选择正确的密钥文件", "密钥文件不存在");
            }
            else
            {
                this.ABox_DES_AES_KEY_PATH = path;
            }
        }

        private void A_RSA_PRI_Button_Click(object sender, EventArgs e)
        {
            String path = this.ABox_A_RSA_PRI_PATH;
            OpenFileDialog keyPathSelector = new OpenFileDialog();
            keyPathSelector.InitialDirectory = "~";
            keyPathSelector.RestoreDirectory = true;
            keyPathSelector.CheckFileExists = true;
            if (keyPathSelector.ShowDialog() == DialogResult.OK)
            {
                path = keyPathSelector.FileName;
                this.ABox_A_RSA_PRI_PATH = path;
                this.A_RSA_PRI_TextBox.Text = path;
            }

        }
        private void B_RSA_PUB_Button_Click(object sender, EventArgs e)
        {
            String path = this.ABox_B_RSA_PUB_PATH;
            OpenFileDialog keyPathSelector = new OpenFileDialog();
            keyPathSelector.InitialDirectory = "~";
            keyPathSelector.RestoreDirectory = true;
            keyPathSelector.CheckFileExists = true;
            if (keyPathSelector.ShowDialog() == DialogResult.OK)
            {
                path = keyPathSelector.FileName;
                this.ABox_B_RSA_PUB_PATH = path;
                this.B_RSA_PUB_TextBox.Text = path;
            }

        }
        private void DES_AES_Button_Click(object sender, EventArgs e)
        {
            String path = this.ABox_DES_AES_KEY_PATH;
            OpenFileDialog keyPathSelector = new OpenFileDialog();
            keyPathSelector.InitialDirectory = "~";
            keyPathSelector.RestoreDirectory = true;
            keyPathSelector.CheckFileExists = true;
            if (keyPathSelector.ShowDialog() == DialogResult.OK)
            {
                path = keyPathSelector.FileName;
                this.ABox_DES_AES_KEY_PATH = path;
                this.DES_AES_TextBox.Text = path;
            }

        }
        //BBox event
        private void B_RSA_PRI_TextBox_Validated(object sender, EventArgs e)
        {
            String path = this.B_RSA_PRI_TextBox.Text;
            if (!File.Exists(path))
            {
                MessageBox.Show("请选择正确的密钥文件", "密钥文件不存在");
            }
            else
            {
                this.BBox_B_RSA_PRI_PATH = path;
            }
        }
        private void A_RSA_PUB_TextBox_Validated(object sender, EventArgs e)
        {
            String path = this.A_RSA_PUB_TextBox.Text;
            if (!File.Exists(path))
            {
                MessageBox.Show("请选择正确的密钥文件", "密钥文件不存在");
            }
            else
            {
                this.BBox_A_RSA_PUB_PATH = path;
            }
        }

        private void B_RSA_PRI_Button_Click(object sender, EventArgs e)
        {
            String path = this.BBox_B_RSA_PRI_PATH;
            OpenFileDialog keyPathSelector = new OpenFileDialog();
            keyPathSelector.InitialDirectory = "~";
            keyPathSelector.RestoreDirectory = true;
            keyPathSelector.CheckFileExists = true;
            if (keyPathSelector.ShowDialog() == DialogResult.OK)
            {
                path = keyPathSelector.FileName;
                this.BBox_B_RSA_PRI_PATH = path;
                this.B_RSA_PRI_TextBox.Text = path;
            }
        }

        private void A_RSA_PUB_Button_Click(object sender, EventArgs e)
        {
            String path = this.BBox_A_RSA_PUB_PATH;
            OpenFileDialog keyPathSelector = new OpenFileDialog();
            keyPathSelector.InitialDirectory = "~";
            keyPathSelector.RestoreDirectory = true;
            keyPathSelector.CheckFileExists = true;
            if (keyPathSelector.ShowDialog() == DialogResult.OK)
            {
                path = keyPathSelector.FileName;
                this.BBox_A_RSA_PUB_PATH = path;
                this.A_RSA_PUB_TextBox.Text = path;
            }
        }

        

        //cross thread delegate

        private void setText(TextBox textBox, String text)
        {
            if (textBox.InvokeRequired)
            {
                textBox.Invoke(new SetText(setText), new object[] { textBox, text });
            }
            else
            {
                textBox.Text = text;
            }
        }

        public void errorHandle(string msg)
        {
            if (this.InvokeRequired)
            {
                this.Invoke(new Error_handle(errorHandle), new object[] { msg });
            }
            else
            {
                MessageBox.Show(this, "密钥错误，请重新选择密钥后再次发送。\n 错误信息:" + msg);
                this.Enabled = true;
            }
        }
        public void sendSuccess_CallBack()
        {
            this.Enabled = true;
            MessageBox.Show(this, "消息发送成功");
        }

        public void received_CallBack(Dictionary<string, byte[]> decode_res)
        {
            string msg = System.Text.Encoding.Default.GetString(decode_res["MSG"]);
            string dhash = BitConverter.ToString(decode_res["DHASH"]);
            string chash = BitConverter.ToString(decode_res["CHASH"]);
            setText(this.B_Plain_TextBox, msg);
            setText(this.B_HASH_CAL_TextBox, chash);
            setText(this.B_HASH_VerifyResult_TextBox, dhash);
            MessageBox.Show(this, "消息接收成功");
            this.Enabled = true;
            this.Focus();
        }

        private void Send_Button_Click(object sender, EventArgs e)
        {
            if (this.A_Plain_TextBox.TextLength == 0)
            {
                MessageBox.Show(this, "请输入内容后再发送。");
                return;
            }
            if (!File.Exists(this.ABox_A_RSA_PRI_PATH) || !File.Exists(this.ABox_B_RSA_PUB_PATH) || 
                !File.Exists(this.ABox_DES_AES_KEY_PATH) || !File.Exists(this.BBox_A_RSA_PUB_PATH) ||
                !File.Exists(this.BBox_B_RSA_PRI_PATH))
            {
                MessageBox.Show(this, "请选择正确的密钥后再发送!");
                return;
            }
            this.Enabled = false;
            Dictionary<string, string> encode_info = new Dictionary<string, string>();
            encode_info.Add("SYM_ENC_METHOD", this.SYM_METHOD);
            encode_info.Add("HASH_FUNCTION", this.HASH_FUNCTION);
            encode_info.Add("A_RSA_PK_PATH", this.ABox_A_RSA_PRI_PATH);
            encode_info.Add("B_RSA_UK_PATH", this.ABox_B_RSA_PUB_PATH);
            encode_info.Add("AES_DES_KEY_PATH", this.ABox_DES_AES_KEY_PATH);
            SocketSender data_sender = new SocketSender(System.Text.Encoding.Default.GetBytes(A_Plain_TextBox.Text), encode_info, this.errorHandle, ip:Config.IP, port:Config.PORT, encoder: Crypt.encode);
            data_sender.start();
        }

    }
}
