using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEView
{
    class Binder
    {
        public Binder() {}
        public Binder(string offset, string data, string description, string value)
        {
            this.offset = offset;
            this.data = data;
            this.description = description;
            this.value = value;
        }

        public string offset { get; set; }
        public string data { get; set; }
        public string description { get; set; }
        public string value { get; set; }

    }
}
