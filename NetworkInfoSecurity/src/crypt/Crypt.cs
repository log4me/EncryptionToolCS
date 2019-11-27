using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace NetworkInfoSecurity.crypt
{
    /// <summary>
    /// 执行加密解密的主要流程
    /// </summary>
    class Crypt
    {
        // 表示消息长度的数据所占长度
        private static readonly int MSG_LENGTH_DATA_LENGTH = BitConverter.GetBytes(Convert.ToInt32(0)).Length;
        // 表示AES/DES加密后消息长度的数据所占长度
        private static readonly int AES_DES_ENCRYPTED_LENGTH_LENGTH = BitConverter.GetBytes(Convert.ToInt32(0)).Length;
        // 按照流程对数据进行编码
        public static byte[] encode(byte[] data, Dictionary<String, String> encode_info)
        {
            // data 为要处理的消息
            byte[] hash = null;
            
            // 计算hash值
            if (encode_info["HASH_FUNCTION"].Equals("MD5"))
            {
                MD5 md5 = new MD5CryptoServiceProvider();
                hash = md5.ComputeHash(data);
            }
            else if (encode_info["HASH_FUNCTION"].Equals("SHA"))
            {
                SHA1 sha1 = new SHA1CryptoServiceProvider();
                hash = sha1.ComputeHash(data);
            }
            else
            {
                throw new Exception("Not Implenmentation Error.");
            }
            //对hash值使用用户a的私钥签名
            PrivateKey a_pk = new PrivateKey(encode_info["A_RSA_PK_PATH"]);
            RSA rsa_a = RSA.GetRsa();
            rsa_a.import_pk(a_pk);
            byte[] encrypted_hash = rsa_a.encrypt_with_pk(hash);
            
            // m_length 代表消息的长度
            Int32 m_length = Convert.ToInt32(data.Length);
            byte[] msg_len_data = BitConverter.GetBytes(m_length);
            // msg_len_msg_encrypted_hash 代表 msg 和用户a的私钥加密的 H(M)的拼接，并附加上4字节的消息长度（ 消息长度||消息||加密后的HASH）
            byte[] msg_len_msg_encrypted_hash = msg_len_data.Concat(data).Concat(encrypted_hash).ToArray<byte>();
            
            // 读取aes_des密钥文件
            FileStream aes_des_key_stream = new FileStream(encode_info["AES_DES_KEY_PATH"], FileMode.Open);
            BinaryReader br = new BinaryReader(aes_des_key_stream);

            int aes_des_key_length = Convert.ToInt32(aes_des_key_stream.Length);
            byte[] aes_des_key = br.ReadBytes(aes_des_key_length);
            br.Close();

            // 建立DES/AES算法
            SymmetricAlgorithm sa = null;
            if (encode_info["SYM_ENC_METHOD"].Equals("DES"))
            {
                sa = new DESCryptoServiceProvider();

            }
            else if (encode_info["SYM_ENC_METHOD"].Equals("AES"))
            {
                sa = new AesCryptoServiceProvider();
            }
            else
            {
                throw new Exception("Not Implenmentation Error.");
            }
            // 使用ECB模式进行加密
            sa.Mode = CipherMode.ECB;
            sa.Key = aes_des_key;
            MemoryStream msEncrypt = new MemoryStream();
            
            CryptoStream csEncrypt = new CryptoStream(msEncrypt, sa.CreateEncryptor(), CryptoStreamMode.Write);
            csEncrypt.Write(msg_len_msg_encrypted_hash, 0, msg_len_msg_encrypted_hash.Length);
            csEncrypt.FlushFinalBlock();
            csEncrypt.Close();
            //aes_des_crypted_data 代表AES/DES加密后的 L(M) || M || E(RKa, H(M))
            byte[] aes_des_crypted_data = msEncrypt.ToArray();
            //加密后的消息长度
            byte[] aes_des_crypted_data_len_data = BitConverter.GetBytes(Convert.ToInt32(aes_des_crypted_data.Length));

            //使用 b的rsa公钥加密 AES_DES_KEY
            RSA rsa_b = RSA.GetRsa();
            PublicKey uk_b = new PublicKey(encode_info["B_RSA_UK_PATH"]);
            rsa_b.import_uk(uk_b);
            byte[] encrypted_aes_des_key = rsa_b.encrypt_with_uk(aes_des_key);
            //把消息拼接到一起
            byte[] encoded_data = (byte[])aes_des_crypted_data_len_data.Concat(aes_des_crypted_data).Concat(encrypted_aes_des_key).ToArray<byte>();
            return encoded_data;
        }
        public static Dictionary<String, byte[]> decode(byte[] data, Dictionary<String, String> decode_info)
        {
            if (data == null) return null;
            // 分离加密后的消息和aes_des_key 
            byte[] aes_des_data_len_data = new byte[AES_DES_ENCRYPTED_LENGTH_LENGTH];
            Array.ConstrainedCopy(data, 0, aes_des_data_len_data, 0, AES_DES_ENCRYPTED_LENGTH_LENGTH);
            int aes_des_data_len = BitConverter.ToInt32(aes_des_data_len_data, 0);
            //int aes_des_data_len = Convert.ToInt32(aes_des_data_len_data);
            byte[] aes_des_encrypted_data = new byte[aes_des_data_len];
            Array.ConstrainedCopy(data, AES_DES_ENCRYPTED_LENGTH_LENGTH, aes_des_encrypted_data, 0, aes_des_data_len);
            int encrypted_aes_des_key_len = data.Length - AES_DES_ENCRYPTED_LENGTH_LENGTH - aes_des_data_len;
            byte[] encrypted_aes_des_key = new byte[encrypted_aes_des_key_len];
            Array.ConstrainedCopy(data, AES_DES_ENCRYPTED_LENGTH_LENGTH + aes_des_data_len, encrypted_aes_des_key, 0, encrypted_aes_des_key_len);

            // 解密aes_des_key
            RSA rsa_b = RSA.GetRsa();
            rsa_b.import_pk(new PrivateKey(decode_info["B_RSA_PK_PATH"]));

            byte[] aes_des_key = rsa_b.decrypt_with_pk(encrypted_aes_des_key);

            // 解密消息和HASH值
            SymmetricAlgorithm sa = null;

            if (decode_info["SYM_ENC_METHOD"].Equals("AES"))
            {
                sa = new AesCryptoServiceProvider();
            }
            else if (decode_info["SYM_ENC_METHOD"].Equals("DES"))
            {
                sa = new DESCryptoServiceProvider();
            }
            else
            {
                throw new Exception("Not implenmentation Error");
            }
            sa.Mode = CipherMode.ECB;
            sa.Key = aes_des_key;
            MemoryStream ms = new MemoryStream();
            CryptoStream cs = new CryptoStream(ms, sa.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(aes_des_encrypted_data, 0, aes_des_encrypted_data.Length);
            cs.FlushFinalBlock();
            cs.Close();
            // 分离消息和HASH值
            byte[] msg_len_msg_encrypted_hash_data = ms.ToArray();
            byte[] msg_len_data = new byte[MSG_LENGTH_DATA_LENGTH];
            Array.ConstrainedCopy(msg_len_msg_encrypted_hash_data, 0, msg_len_data, 0, MSG_LENGTH_DATA_LENGTH);
            int msg_len = BitConverter.ToInt32(msg_len_data, 0);
            //int msg_len = Convert.ToInt32(msg_len_data);
            byte[] msg = new byte[msg_len];
            Array.ConstrainedCopy(msg_len_msg_encrypted_hash_data, MSG_LENGTH_DATA_LENGTH, msg, 0, msg_len);
            int hash_len = msg_len_msg_encrypted_hash_data.Length - MSG_LENGTH_DATA_LENGTH - msg_len;
            byte[] encrypted_hash = new byte[hash_len];
            Array.ConstrainedCopy(msg_len_msg_encrypted_hash_data, MSG_LENGTH_DATA_LENGTH + msg_len, encrypted_hash, 0, hash_len);

            // 解密HASH值
            RSA rsa_a = RSA.GetRsa();
            rsa_a.import_uk(new PublicKey(decode_info["A_RSA_UK_PATH"]));
            byte[] decrypted_hash = rsa_a.decrypt_with_uk(encrypted_hash);
            // 重新计算HASH值
            byte[] calculated_hash = null;
            if (decode_info["HASH_FUNCTION"].Equals("MD5"))
            {
                MD5 md5 = new MD5CryptoServiceProvider();
                calculated_hash = md5.ComputeHash(msg);
            }
            else if (decode_info["HASH_FUNCTION"].Equals("SHA"))
            {
                SHA1 sha1 = new SHA1CryptoServiceProvider();
                calculated_hash = sha1.ComputeHash(msg);
            }
            else
            {
                throw new Exception("Not Implenmentation Error.");
            }
            Dictionary<String, byte[]> res = new Dictionary<string, byte[]>();
            res.Add("MSG", msg);
            res.Add("DHASH", decrypted_hash);
            res.Add("CHASH", calculated_hash);
            return res;
        }

    }
}
