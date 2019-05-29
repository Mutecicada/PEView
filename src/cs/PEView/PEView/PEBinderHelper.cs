using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEView
{
    class PEBinderHelper
    {
        uint[] dos_offset = new uint[]                          // PEHeaders.DOS_HEADER Member Size
        { };
        string[] dos_des = new string[]                         // PEHeaders.DOS_HEADER Member Description
        {};
        uint[] nt_offset = new uint[]
        { };
        string[] nt_des = new string[]
        {};

        uint[] section_offset = new uint[]
        { };
        string[] section_des = new string[]
        {};

    }
}
