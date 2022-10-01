using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OS_Scanner
{
    public partial class Form3 : Form
    {
        public Form3()
        {
            InitializeComponent();
        }
        Image DownloadImage(string fromUrl)
        {
            using (System.Net.WebClient webClient = new System.Net.WebClient())
            {
                using (Stream stream = webClient.OpenRead(fromUrl))
                {
                    return Image.FromStream(stream);
                }
            }
        }
        private void Form3_Load(object sender, EventArgs e)
        {
            if (Form1.urlGif != "")
            {
                guna2PictureBox1.Image = DownloadImage(Form1.urlGif);
            }
        }
    }
}
