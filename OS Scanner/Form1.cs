using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace OS_Scanner
{
    public partial class Form1 : Form
    {

        private int F;
        public Form1()
        {
            InitializeComponent();
        }

        public static int a = 0;

        public static string pinUsed = "";
        public static string author = "";
        public static bool showResultsOnPage = false;

        private string GetOSFriendlyName()
        {

            string result = string.Empty;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem");
            foreach (ManagementObject os in searcher.Get())
            {
                result = os["Caption"].ToString();
                break;
            }
            return result;
        }

        private void doLogin(string pin)
        {
            try
            {

                var url = "https://os-scanner.site/pins";

                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["pin"] = pin;
                    var response = wb.UploadValues(url, "POST", data);
                    string responseInString = Encoding.UTF8.GetString(response);

                    if (responseInString.Contains("plan"))
                    {
                        var userId = responseInString.Split('\n');
                        author = userId[1];
                        getCustomStrings(userId[1]);
                        getCustomFiles(userId[1]);
                    }

                    if (responseInString == "Você não pode usar seu próprio pin!")
                    {
                        MessageBox.Show("Sorry, but you can't test the tool, use it during a ScreenShare.");
                        guna2Panel2.Controls.Clear();
                    }

                    if (!responseInString.Contains("found"))
                    {
                        MessageBox.Show("Pin Inválido! ", "O.S Technologies");
                    }

                    else
                    {

                        pinUsed = pin;

                        Form3 form3 = new Form3();
                        form3.TopLevel = false;
                        if (!GetOSFriendlyName().Contains("7"))
                        {
                            guna2Panel2.Controls.Clear();
                            guna2Panel2.Controls.Add(form3);
                            form3.Show();
                            form3.Visible = true;
                        }
                        timer1.Start();
                    }
                }
          } catch
            {
                MessageBox.Show("Houve um erro!");
            }
        }
        private void getCustomStrings(string id)
        {
            try
            {
                var url = "https://os-scanner.site/CustomStrings";
                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["id"] = id;
                    var response = wb.UploadValues(url, "POST", data);
                    string responseInString = Encoding.UTF8.GetString(response);
                    JArray array = JArray.Parse(responseInString);
                    foreach (JObject obj in array.Children<JObject>())
                    {
                        CustomStrings.Add("process$" + obj["process"].ToString() + "$string$" + obj["str"].ToString() + "$name$" + obj["name"]);
                    }
                }
            }
            catch { }
        }

        private void getCustomFiles(string id)
        {
            try
            {
                var url = "https://os-scanner.site/api/CustomFiles";

                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["id"] = id;
                    var response = wb.UploadValues(url, "POST", data);
                    string responseInString = Encoding.UTF8.GetString(response);

                    JArray array = JArray.Parse(responseInString);

                    foreach (JObject obj in array.Children<JObject>())
                    {
                        CustomFiles.Add("filehash$" + obj["fileHash"].ToString() + "$name$" + obj["name"].ToString());
                    }
                }
            }
            catch
            {

            }
        }

        public static List<string> CustomFiles = new List<string>();
        public static List<string> CustomStrings = new List<string>();

        public static string json = "";

        public string GetAddressString(string address)
        {
            WebClient client = new WebClient();
            string reply = client.DownloadString(address);
            return reply;
        }
        public string PostAddressString(string address, string where, string what)
        {
            WebClient client = new WebClient();
            var data = new NameValueCollection();
            data[where] = what;
            var response = client.UploadValues(address, "POST", data);
            string reply = Encoding.UTF8.GetString(response);
            return reply;
        }

        public Color convertToColorArray(string str)
        {
            var colorArray = new Color();
            for (int i = 0; i < str.Split(',').Length; i++)
            {
                var splitted = str.Split(',');
                colorArray = Color.FromArgb(Convert.ToInt32(splitted[0]), Convert.ToInt32(splitted[1]), Convert.ToInt32(splitted[2]));
            }
            return colorArray;
        }

        public static string urlGif;

        public string GetMD5(string filename)
        {
            try
            {
                FileStream file = new FileStream(filename, FileMode.Open);
                MD5 md5 = new MD5CryptoServiceProvider();
                byte[] retVal = md5.ComputeHash(file);
                file.Close();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < retVal.Length; i++)
                {
                    sb.Append(retVal[i].ToString("x2"));
                }
                return sb.ToString();
            }
            catch { return ""; }
        }

        List<string> analisedItens = new List<string>();

        private void ListProcesses()
        {
        //    var antissHash = GetAddressString("https://os-scanner.site/api/antiss");
        //    string query = "SELECT ExecutablePath, ProcessID FROM Win32_Process";
        //    ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);

        //    foreach (ManagementObject item in searcher.Get())
        //    {
        //        object id = item["ProcessID"];
        //        object path = item["ExecutablePath"];

        //        if (path != null)
        //        {
        //            if (!analisedItens.Contains(path.ToString()))
        //            {
        //                if (GetMD5(path.ToString()) == antissHash)
        //                {
        //                    MessageBox.Show("AntiSS Detected! Killing Process: " + id.ToString());
        //                    Process.GetProcessById((int)id).Kill();
        //                }
        //                analisedItens.Add(path.ToString());
        //            }
        //        }
        //    }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            ListProcesses();
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            var strExeFilePath = Assembly.GetExecutingAssembly().Location;
            var name = Path.GetFileNameWithoutExtension(strExeFilePath);
            if (!GetOSFriendlyName().Contains("7"))
            {
                try
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    var contents = GetAddressString("https://os-scanner.site/api/GetInterface");
                    JArray array = JArray.Parse(contents);
                    foreach (JObject obj in array.Children<JObject>())
                    {
                        urlGif = obj["Form1"]["loadingGif"].ToString();
                        guna2Panel1.BackColor = convertToColorArray(obj["Form1"]["panelColor"].ToString());
                        guna2Panel2.BackColor = convertToColorArray(obj["Form1"]["panelColor"].ToString());
                        t1.FillColor = convertToColorArray(obj["Form1"]["boxColor"].ToString());
                        t2.FillColor = convertToColorArray(obj["Form1"]["boxColor"].ToString());
                        t3.FillColor = convertToColorArray(obj["Form1"]["boxColor"].ToString());
                        t4.FillColor = convertToColorArray(obj["Form1"]["boxColor"].ToString());
                        t5.FillColor = convertToColorArray(obj["Form1"]["boxColor"].ToString());
                        guna2ControlBox2.BackColor = convertToColorArray(obj["Form1"]["panelColor"].ToString());
                        guna2ControlBox1.BackColor = convertToColorArray(obj["Form1"]["panelColor"].ToString());
                    }
                }
                catch { }
            }
            try
            {
                var hosts = File.ReadAllText(@"C:\Windows\System32\drivers\etc\hosts");
                if (hosts.Contains("os-scanner"))
                {
                    MessageBox.Show("Bypass attempt detected: Website Blocking Detected!");
                }
            }
            catch
            {

            }

            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                var response = PostAddressString("https://os-scanner.site/api/CheckName", "name", name);
                if (response != "not found")
                {
                    Form3 form3 = new Form3();
                    form3.TopLevel = false;
                    if (!GetOSFriendlyName().Contains("7"))
                    {
                        guna2Panel2.Controls.Clear();
                        guna2Panel2.Controls.Add(form3);
                        form3.Show();
                        form3.Visible = true;
                    }
                    doLogin(response);
                }
            }
            catch { }

        }

        private void t1_TextChanged(object sender, EventArgs e)
        {
            if (t1.Text.Length == 5)
            {
                var pin = t1.Text;
                t1.Text = pin[0].ToString();
                t2.Text = pin[1].ToString();
                t3.Text = pin[2].ToString();
                t4.Text = pin[3].ToString();
                t5.Text = pin[4].ToString();
            }
            if (t1.Text == "")
            {
                t1.Select();
            }
            else
            {
                t2.Select();
            }
            t1.DeselectAll();
        }
        private void t2_TextChanged(object sender, EventArgs e)
        {
            if (t2.Text == "")
            {
                t1.Select();
            }
            else
            {
                t3.Select();
            }
        }

        private void t3_TextChanged(object sender, EventArgs e)
        {
            if (t3.Text == "")
            {
                t2.Select();
            }
            else
            {
                t4.Select();
            }
        }

        private void t4_TextChanged(object sender, EventArgs e)
        {
            if (t4.Text == "")
            {
                t3.Select();
            }
            else
            {
                t5.Select();
            }
        }

        private void t5_TextChanged(object sender, EventArgs e)
        {
            if (t5.Text == "")
            {
                t4.Select();
            }
            else
            {
                var FinalLoginPin = t1.Text + t2.Text + t3.Text + t4.Text + t5.Text;
                doLogin(FinalLoginPin);
            }
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            F += 1;

            if (F == 3)
            {
                Form2 form2 = new Form2();
                form2.TopLevel = false;
                guna2Panel2.Controls.Clear();
                guna2Panel2.Controls.Add(form2);
                form2.Show();
            }
        }
    }
}
