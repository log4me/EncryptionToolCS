using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
namespace NetworkInfoSecurity.crypt
{
    public class PublicKey
    {
        private int n_length_length = BitConverter.GetBytes(Convert.ToInt32(0)).Length;
        private BigInteger n;
        private BigInteger e;
        public PublicKey(BigInteger n, BigInteger e)
        {
            this.n = n;
            this.e = e;
        }
        public PublicKey(string keyFile)
        {
            FileStream fs = new FileStream(keyFile, FileMode.Open);
            BinaryReader br = new BinaryReader(fs);
            int key_length = Convert.ToInt32(fs.Length);
            byte[] key_data = br.ReadBytes(key_length);
            br.Close();
            byte[] n_length_data = new byte[n_length_length];
            Array.ConstrainedCopy(key_data, 0, n_length_data, 0, n_length_length);
            int n_length = BitConverter.ToInt32(n_length_data, 0);
            //int n_length = Convert.ToInt32(n_length_data);
            byte[] n_data = new byte[n_length];
            Array.ConstrainedCopy(key_data, n_length_length, n_data, 0, n_length);
            int e_length = key_data.Length - n_length_length - n_length;
            byte[] e_data = new byte[e_length];
            Array.ConstrainedCopy(key_data, n_length_length + n_length, e_data, 0, e_length);
            this.n = new BigInteger(n_data);
            this.e = new BigInteger(e_data);
        }
        public BigInteger getN()
        {
            return n;
        }
        public BigInteger getE()
        {
            return e;
        }
        public void saveToFile(string filename)
        {
            byte[] n_data = this.n.ToByteArray();
            byte[] e_data = this.e.ToByteArray();
            BinaryWriter bw = new BinaryWriter(new FileStream(filename, FileMode.Create));
            bw.Write(BitConverter.GetBytes(Convert.ToInt32(n_data.Length)));
            bw.Write(n_data);
            bw.Write(e_data);
            bw.Close();
        }
    }
    public class PrivateKey
    {
        private BigInteger n;
        private BigInteger d;
        private int n_length_length = BitConverter.GetBytes(Convert.ToInt32(0)).Length;
        public PrivateKey(BigInteger n, BigInteger d)
        {
            this.n = n;
            this.d = d;
        }
        public PrivateKey(string key_path)
        {
            FileStream fs = new FileStream(key_path, FileMode.Open);
            BinaryReader br = new BinaryReader(fs);
            int key_length = Convert.ToInt32(fs.Length);
            byte[] key_data = br.ReadBytes(key_length);
            br.Close();
            byte[] n_length_data = new byte[n_length_length];
            Array.ConstrainedCopy(key_data, 0, n_length_data, 0, n_length_length);
            int n_length = BitConverter.ToInt32(n_length_data, 0);
            //int n_length = Convert.ToInt32(n_length_data);
            byte[] n_data = new byte[n_length];
            Array.ConstrainedCopy(key_data, n_length_length, n_data, 0, n_length);
            int e_length = key_data.Length - n_length_length - n_length;
            byte[] e_data = new byte[e_length];
            Array.ConstrainedCopy(key_data, n_length_length + n_length, e_data, 0, e_length);
            this.n = new BigInteger(n_data);
            this.d = new BigInteger(e_data);
        }
        public BigInteger getN()
        {
            return n;
        }
        public BigInteger getD()
        {
            return d;
        }
        public void saveToFile(string filename)
        {
            byte[] n_data = this.n.ToByteArray();
            byte[] d_data = this.d.ToByteArray();
            BinaryWriter bw = new BinaryWriter(new FileStream(filename, FileMode.Create));
            bw.Write(BitConverter.GetBytes(Convert.ToInt32(n_data.Length)));
            
            bw.Write(n_data);
            bw.Write(d_data);
            bw.Close();
        }
    }
    public class RsaKeyPair
    {
        private PrivateKey privateKey;
        private PublicKey publicKey;
        public RsaKeyPair(PublicKey publicKey, PrivateKey privateKey)
        {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
        public PrivateKey getPrivateKey()
        {
            return privateKey;
        }
        public PublicKey getPublicKey()
        {
            return publicKey;
        }
    }
    public class RSAGeneratorKey
    {
        public static RsaKeyPair generatorKey(int bitLength)
        {
            Random random = new Random();
            BigInteger p = new BigInteger(bitLength, random);
            while (!p.IsProbablePrime(32))
            {
                p = p.NextProbablePrime();
            }
            BigInteger q = new BigInteger(bitLength, random);
            while (!q.IsProbablePrime(32))
            {
                q = q.NextProbablePrime();
            }
            BigInteger n = p.Multiply(q);
            BigInteger k = p.Subtract(BigInteger.One).Multiply(q.Subtract(BigInteger.One));
            BigInteger e = BigInteger.ProbablePrime(bitLength - 1, random);
            while (!e.Gcd(k).Equals(BigInteger.One))
            {
                e = e.NextProbablePrime();
            }
            BigInteger d = e.ModInverse(k);
            PrivateKey pk = new PrivateKey(n, d);
            PublicKey uk = new PublicKey(n, e);
            return new RsaKeyPair(uk, pk);
        }
    }
    public class RSA
    {
        private bool has_pk = false;
        private bool has_uk = false;
        private PublicKey uk = null;
        private PrivateKey pk = null;
        private RSA()
        { 
        }
        public static RSA GetRsa()
        {
            return new RSA();
        }
        public void import_uk(PublicKey uk)
        {
            this.uk = uk;
            has_uk = true;
        }
        public void import_pk(PrivateKey pk)
        {
            this.pk = pk;
            has_pk = true;
        }
        public void import_key_pait(RsaKeyPair key_pair)
        {
            this.pk = key_pair.getPrivateKey();
            this.uk = key_pair.getPublicKey();
            has_pk = true;
            has_uk = true;
        }
        private byte[] encrypt(byte[] data, BigInteger n, BigInteger key)
        {
            BigInteger m = new BigInteger(1, data);
            if (m.BitLength > n.BitLength)
            {
                throw new Exception("data to be encrypted is too long");
            }
            return m.ModPow(key, n).ToByteArrayUnsigned();
            
        }
        public byte[] encrypt_with_pk(byte[] data)
        {
            if (!has_pk)
            {
                throw new Exception("Please import private key first");
            }

            return this.encrypt(data, this.pk.getN(), this.pk.getD());
        }
        public byte[] decrypt_with_pk(byte[] data)
        {
            return this.encrypt_with_pk(data);
        }
        public byte[] encrypt_with_uk(byte[] data)
        {
            if (!has_uk)
            {
                throw new Exception("Please import private key first");
            }
            return this.encrypt(data, this.uk.getN(), this.uk.getE());
        }
        public byte[] decrypt_with_uk(byte[] data)
        {
            return this.encrypt_with_uk(data);
        }
    }
}