using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Diagnostics;
using System.Xml.Linq;

namespace PEView
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        PEHeaders pe = new PEHeaders();

        string FilePathDlg()
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                return ofd.FileName;
            }
            else
            {
                return null;
            }
        }

        public MainWindow()
        {
            InitializeComponent();

            string strFileName = FilePathDlg();

            FileStream fp = new FileStream(strFileName, FileMode.Open, FileAccess.Read);
            if (fp == null)
            {
                Console.WriteLine("FIle Open Error");
            }

            pe.dos_header = (PEHeaders._DOS_HEADER)pe.read_header(fp, typeof(PEHeaders._DOS_HEADER));
            Console.WriteLine("DOS Signature : " + String.Join("", pe.dos_header.e_magic));

            byte[] machine = new byte[2];
            fp.Seek(pe.dos_header.e_lfanew + 4, SeekOrigin.Begin);
            fp.Read(machine, 0, 2);


            int numberofsections;
            fp.Seek(pe.dos_header.e_lfanew, SeekOrigin.Begin);
            if (BitConverter.ToInt16(machine, 0) == 0x014c)                 // 32bit
            {
                pe.nt_header32 = (PEHeaders._NT_HEADERS32)pe.read_header(fp, typeof(PEHeaders._NT_HEADERS32));
                numberofsections = pe.nt_header32.FileHeader.NumberOfSections;
                pe.is32 = true;
            }
            else                                                            // 64 bit
            {
                pe.nt_header64 = (PEHeaders._NT_HEADERS64)pe.read_header(fp, typeof(PEHeaders._NT_HEADERS64));
                numberofsections = pe.nt_header64.FileHeader.NumberOfSections;
                pe.is32 = false;
            }

            pe.section_headers = new PEHeaders._SECTION_HEADER[numberofsections];
            for (int i = 0; i < numberofsections; i++)
            {
                pe.section_headers[i] = (PEHeaders._SECTION_HEADER)pe.read_header(fp, typeof(PEHeaders._SECTION_HEADER));
            }

            for (int i = 0; i < numberofsections; i++)
            {
                TreeViewItem section = new TreeViewItem();
                section.Header = String.Join("", pe.section_headers[i].Name);
             // section.Name = String.Join("", pe.section_headers[i].Name);
                PETop.Items.Add(section);
            }

            pe.setBinderList();
            
        }

        private void PETree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            TreeViewItem item = PETree.SelectedItem as TreeViewItem;
            
            if (!item.HasItems)
            {
                string header = item.Header as string;
                switch (header)
                {
                    case "DOS_HEADERS" :
                        MyList.ItemsSource = pe.dos_binder;
                        break;

                    case "DOS_STUB" :
                        MyList.ItemsSource = pe.nt_binder;
                        break;
                        
                    case "Signautre" :
                        MyList.ItemsSource = pe.nt_binder.GetRange(0, 1);
                        break;

                    case "FILE_HEADER" :
                        MyList.ItemsSource = pe.nt_binder.GetRange(1, 7);
                        
                        break;

                    case "OPTIONAL_HEADER" :
                        MyList.ItemsSource = pe.nt_binder;
                        break;
                }


            }
            else
            {
               
            }


        }
    }
}
