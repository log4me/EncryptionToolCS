using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkInfoSecurity.network
{
    abstract class Thread
    {
        System.Threading.Thread thread = null;
        bool isDaemon = true;
        public Thread(bool isDaemon = true)
        {
            this.isDaemon = isDaemon;
        }
        abstract public void run();
        public void start()
        {
            if (thread == null)
            {
                thread = new System.Threading.Thread(run);
                thread.IsBackground = this.isDaemon;
            }
            thread.Start();
        }
    }
}
