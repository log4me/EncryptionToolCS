using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkInfoSecurity.config
{
    class Config
    {
        public static readonly int PORT = 6666;
        public static readonly string IP = "127.0.0.1";
        public static readonly int AES_KEY_LENGTH = 256 / 8;
        public static readonly int RSA_KEY_LENGTH = 1024;
    }
}
