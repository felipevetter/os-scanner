using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace OS_Scanner
{
    public partial class Form2 : Form
    {
        public Form2()
        {
            InitializeComponent();
        }

        private List<string> detections = new List<string>();
        private List<string> file_activity = new List<string>();
        private string last_usb_use;
        private string usb_letter;

        public static string tempPath = @"C:\Windows\Temp";

        public string GetMD5(string filename)
        {
            try
            {
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filename))
                    {
                        var hash = md5.ComputeHash(stream);
                        
                        foreach (string customFiles in Form1.CustomFiles)
                        {
                            if (BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant() == customFiles.Split('$')[1])
                            {
                                detections.Add("Custom File: " + customFiles[3] + " At: " + filename);
                            }
                        }


                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }
            }
            catch { return ""; }
        }
        //Stopwatch
        Stopwatch stopwatch = new Stopwatch();

        private void sendScan()
        {
            try
            {
                var url = "";
                if (GetOSFriendlyName().Contains("7"))
                {
                    url = "http://os-scanner.site/api/SendScan";
                }
                else
                {
                    url = "https://os-scanner.site/api/SendScan";
                }
                
                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["author"] = Form1.author;
                    data["pinUsado"] = Form1.pinUsed;
                    data["username"] = getMinecraftUsernames();
                    if (isUsingVPN())
                    {
                        data["isVPN"] = "Sim";
                    }
                    else
                    {
                        data["isVPN"] = "Não";
                    }
                    string minutes;
                    try
                    {
                        minutes = Convert.ToInt32(stopwatch.Elapsed.Minutes) + "m, ";

                    } catch { minutes = "?m, "; }
                    string seconds;
                    try
                    {
                        seconds = Convert.ToInt32(stopwatch.Elapsed.Seconds) + "s, ";
                    } catch { seconds = "?s, "; }
                    string ms;
                    try
                    {
                        ms = Convert.ToInt32(stopwatch.Elapsed.Milliseconds) + "ms";
                    } catch { ms = "?ms"; }
                    data["ScanTime"] = minutes + seconds + ms;
                    data["OperationalSystem"] = GetOSFriendlyName();
                    data["RecycleBinModify"] = CompareDate(File.GetLastWriteTime(@"C:\$Recycle.Bin\" + WindowsIdentity.GetCurrent().User.ToString())).ToString();
                    if (isVM())
                    {
                        data["isVM"] = "Sim";
                    }
                    else
                    {
                        data["isVM"] = "Não";
                    }
                    if (detections.Count > 0)
                    { 
                        foreach (string detect in detections)
                        {
                           data["detections"] += detect + ", ";
                        }  
                    } 
                    else
                    {
                        data["detections"] = "";
                    }

                    if (file_activity.Count > 0)
                    {
                        foreach (string detect in file_activity)
                        {
                            data["file_activity"] += detect + ", ";
                        }
                    }
                    else
                    {
                        data["file_activity"] = "";
                    }
                    data["last_usb"] = last_usb_use;
                    data["usb_letter"] = usb_letter;
                    data["dpsTime"] = GetProcessInitialDateById(GetService("DPS"));
                    data["explorerTime"] = GetProcessInitialDate("explorer");
                    data["dnsTime"] = GetProcessInitialDateById(GetService("Dnscache"));
                    data["diagTime"] = GetProcessInitialDateById(GetService("DiagTrack"));
                    data["pcaTime"] = GetProcessInitialDateById(GetService("PcaSvc"));
                    data["searchTime"] = GetProcessInitialDate("SearchIndexer");
                    data["time"] = DateTime.Now.ToString();
                    wb.UploadValues(url, "POST", data);
                    wb.Proxy = null;
                }
            }
            catch (Exception e) { MessageBox.Show(e.ToString()); }
        }

        List<string> usernames = new List<string>();

        private void scanShiginima()
        {
            try
            {
                var result = File.ReadAllText($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\usercache.json");
                JArray array = JArray.Parse(result);
                foreach (JObject obj in array.Children<JObject>())
                {
                    if (!usernames.Contains(obj["name"].ToString()))
                    {
                        usernames.Add(obj["name"].ToString());
                    }
                }
            }
            catch { }
        }
        private void scanTLauncher()
        {
            foreach(string line in File.ReadLines($@"C:\Users\{Environment.UserName}\AppData\Roaming\.minecraft\TlauncherProfiles.json"))
            {
                if(line.Contains("\"username\""))
                {
                    var usuario = line.Split(':')[1];
                    var user = usuario.Split('"')[1];
                    if (!usernames.Contains(user))
                    {
                        usernames.Add(user);
                    }
                }
            }
        }
        private string getMinecraftUsernames()
        {
            
            try
            {
                scanShiginima();
                scanTLauncher();  
                var minecraftUsers = "";
               
                for (int j = 0; j < usernames.Count(); j++)
                {
                    minecraftUsers = minecraftUsers + usernames[j] + " ";
                }
                return minecraftUsers;
            }
            catch
            {
                return "Unknow User";
            }
        }
        private static bool isVM()
        {
            bool foundMatch = false;
            ManagementObjectSearcher search1 = new ManagementObjectSearcher("select * from Win32_BIOS");
            var enu = search1.Get().GetEnumerator();
            if (!enu.MoveNext()) throw new Exception("Unexpected WMI query failure");
            string biosVersion = enu.Current["version"].ToString();
            string biosSerialNumber = enu.Current["SerialNumber"].ToString();

            try
            {
                foundMatch = Regex.IsMatch(biosVersion + " " + biosSerialNumber, "VMware|VIRTUAL|A M I|Xen|VirtualBox", RegexOptions.IgnoreCase);
            }
            catch
            {

            }

            ManagementObjectSearcher search2 = new ManagementObjectSearcher("select * from Win32_ComputerSystem");
            var enu2 = search2.Get().GetEnumerator();
            if (!enu2.MoveNext()) throw new Exception("Unexpected WMI query failure");
            string manufacturer = enu2.Current["manufacturer"].ToString();
            string model = enu2.Current["model"].ToString();

            try
            {
                foundMatch = Regex.IsMatch(manufacturer + " " + model, "Microsoft|VMWare|Virtual", RegexOptions.IgnoreCase);
            }
            catch
            {
                // Syntax error in the regular expression
            }

            return foundMatch;
        }

        private int GetService(string Service)
        {
            try
            {
                ServiceController[] srvc = ServiceController.GetServices();
                foreach (var sr in srvc)
                {
                    if (sr.ServiceName == Service)
                    {
                        // get status
                        var status = sr.Status.ToString();
                        // get id
                        ManagementObject wmiService;
                        wmiService = new ManagementObject("Win32_Service.Name='" + $"{Service}" + "'");
                        wmiService.Get();
                        var id = Convert.ToInt32(wmiService["ProcessId"]);
                        return id;
                    }
                }
            }
            catch
            {

            }
            return 0;
        }

        private void SingleMD5(string MD5)
        {
            try
            {
                var url = "";
                if (GetOSFriendlyName().Contains("7"))
                {
                    url = "http://os-scanner.site/api/CheckFileHash";
                }
                else
                {
                    url = "https://os-scanner.site/api/CheckFileHash";
                }
                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";

                    foreach (string filehash in MD5s)
                    {
                        data["hash"] += $"{filehash}\n";
                    }
                    var response = wb.UploadValues(url, "POST", data);
                    wb.Proxy = null;
                    string responseInString = Encoding.UTF8.GetString(response);
                    if (responseInString.Contains("Found: "))
                    {
                        detections.Add(responseInString);
                        cheatsCaught.Add(MD5);
                    }
                }
            }
            catch { }
        }

        private void CheckMD5()
        {
            try
            {
                var url = "";
                if (GetOSFriendlyName().Contains("7"))
                {
                    url = "http://os-scanner.site/api/CheckHashs";
                }
                else
                {
                    url = "https://os-scanner.site/api/CheckHashs";
                }
                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";

                    foreach (string filehash in MD5s)
                    {
                        data["hash"] += $"{filehash}\n";
                    }
                    var response = wb.UploadValues(url, "POST", data);
                    string responseInString = Encoding.UTF8.GetString(response);
                    wb.Proxy = null;
                    var obj = JsonConvert.DeserializeObject(responseInString);
                    foreach (var item in ((JArray)obj))
                    {
                        detections.Add(item.ToString());
                        var fileName = item.ToString().Split(new string[] { " at: " }, StringSplitOptions.None);
                        cheatsCaught.Add(GetMD5(fileName[1].Replace("$", "")));
                    }
                }
            }
            catch { }
        }

        public string resourceLocal = tempPath + "\\os_rec.exe";
        public string resourceLocal2 = tempPath + "\\os_recc.exe";
        public string resourceLocal3 = tempPath + "\\os_dir.exe";
        public string USBDebg = tempPath + "\\usbcheck.exe";

        private void CheckStrings(string Strings, string Process)
        {
            try
            {
                var url = "";
                if (GetOSFriendlyName().Contains("7"))
                {
                    url = "http://os-scanner.site/api/CheckStrings";
                }
                else
                {
                    url = "https://os-scanner.site/api/CheckStrings";
                }
                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["string"] = Strings;
                    data["processName"] = Process;
                    var response = wb.UploadValues(url, "POST", data);
                    wb.Proxy = null;
                    string responseInString = Encoding.UTF8.GetString(response);
                    var obj = JsonConvert.DeserializeObject(responseInString);
                    foreach (var item in ((JArray)obj))
                    {
                        if (item.ToString().Contains("Found"))
                        {
                            detections.Add(item.ToString());
                        }
                    }
                }
            }
            catch { }
        }
        private bool isTryingToBypass()
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
                RegistryKey key2 = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched");
                if (key != null)
                {
                    if (key.ValueCount < 20)
                    {
                        return true;
                    }
                }
                if(key2 != null)
                {
                    if(key2.ValueCount < 20) 
                    {
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }
        private string GetProcessInitialDate(string Processo)
        {
            try
            {
                Process process = Process.GetProcessesByName(Processo)[0];
                var processTime = Process.GetProcessById(process.Id).StartTime;
                var hoje = DateTime.Now;
                var totalDifference = (hoje - processTime).Minutes;
                var totalDifferenceHr = (hoje - processTime).TotalHours;
                var retorno = Convert.ToInt32(totalDifferenceHr) + " hours and " + Convert.ToInt32(totalDifference) + " minutes ago";
                return retorno;
            }
            catch (Exception e) { reportBug(e.ToString()); }
            return "Unknow";
        }

        private string GetProcessInitialDateById(int Id)
        {
            try
            {
                var processTime = Process.GetProcessById(Id).StartTime;
                var hoje = DateTime.Now;
                var totalDifference = (hoje - processTime).Minutes;
                var totalDifferenceHr = (hoje - processTime).TotalHours;
                var retorno = Convert.ToInt32(totalDifferenceHr) + " hours and " + Convert.ToInt32(totalDifference) + " minutes ago";
                return retorno;
            }
            catch (Exception e) { reportBug(e.ToString()); }
            return "Unknow";
        }
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

        private bool isUsingVPN()
        {
            try
            {
                using (var wb = new WebClient())
                {
                    var url = "";
                    if (GetOSFriendlyName().Contains("7"))
                    {
                        url = "http://os-scanner.site/api/proxy";
                    } else
                    {
                        url = "https://os-scanner.site/api/proxy";
                    }
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["scanner"] = "isScanner";
                    var response = wb.UploadValues(url, "POST", data);
                    wb.Proxy = null;
                    string responseInString = Encoding.UTF8.GetString(response);
                    if (responseInString == "true")
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch { return false; }
        }

        List<string> MD5s = new List<string>();

        private string generateFileName(int length)
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private int count = 0;

        private bool CheckSize(string Path)
        {
            try
            {
                FileInfo fs = new FileInfo(Path);
                long FileSize = fs.Length / (1024 * 1024);
                if (FileSize < 15)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
        private string heurDll;
        private string heurExe;
        private string heurJar;
        private string heurJarNg;
        private void reportBug(string report)
        {
            var errorId = Guid.NewGuid();
            try
            {
                var url = "";
                if (GetOSFriendlyName().Contains("7"))
                {
                    url = "http://os-scanner.site/api/bugReport";
                }
                else
                {
                    url = "https://os-scanner.site/api/bugReport";
                }
                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["reportId"] = errorId.ToString();
                    data["report"] = report;
                    var response = wb.UploadValues(url, "POST", data);
                    wb.Proxy = null;
                }
            }
            catch
            {

            }
        }

        private void deleteTrash()
        {
            File.Delete(tempPath + "\\analysis.txt");
            File.Delete(tempPath + "\\AnalysisFile.txt");
            File.Delete(resourceLocal);
            File.Delete(resourceLocal2);
            File.Delete(resourceLocal3);
        }

        private void getHeurs() //step 3
        {
            try
            {
                var url = "";
                if (GetOSFriendlyName().Contains("7"))
                {
                    url = "http://os-scanner.site/api/getStrs";
                }
                else
                {
                    url = "https://os-scanner.site/api/getStrs";
                }
                using (var wb = new WebClient())
                {
                    var data = new NameValueCollection();
                    data["apiKey"] = "8C16FE574E540B3CA666DA87065FF11FD9EC0D62EE5A0F73B";
                    data["isScanner"] = "os";
                    var response = wb.UploadValues(url, "POST", data);
                    wb.Proxy = null;
                    string responseInString = Encoding.UTF8.GetString(response);
                    JArray array = JArray.Parse(responseInString);
                    foreach (JObject obj in array.Children<JObject>())
                    {
                        heurDll = obj["heurDll"].ToString();
                        heurExe = obj["heurExe"].ToString();
                        heurJar = obj["heurJar"].ToString();
                        heurJarNg = obj["heurJarNg"].ToString();
                    }
                }
            }
            catch { }
        }

        List<string> cheatsCaught = new List<string>();

        private void HeuristicAnalysis(string type, string type2) // step 5
        {
            try
            {
                count++;
                this.Invoke((MethodInvoker)delegate
                {
                    int x = (guna2Panel2.Size.Width - label1.Width) / 2;
                    int y = ((guna2Panel2.Size.Height - label1.Height) / 2) + 40;
                    label1.Location = new Point(x, y);
                    label1.Text = "Hold On! Running heuristic analysis...";
                });
                progressBaar.Value = count;
                Process externalApp = new Process();
                externalApp.StartInfo.FileName = "findstr";
                externalApp.StartInfo.WorkingDirectory = $"C:\\Users\\{Environment.UserName}";
                externalApp.StartInfo.Arguments = $"/s /m /i /d:C:\\Users\\{Environment.UserName}\\Desktop;C:\\Users\\{Environment.UserName}\\Downloads;C:\\Users\\{Environment.UserName}\\Documents;C:\\Users\\{Environment.UserName}\\AppData\\Local\\Temp\\AnalysisFolder;C:\\Users\\{Environment.UserName}\\AppData\\Roaming\\.minecraft;{tempPath} \"{type}\" *.{type2}";
                externalApp.StartInfo.CreateNoWindow = true;
                externalApp.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                externalApp.StartInfo.UseShellExecute = false;
                externalApp.StartInfo.RedirectStandardOutput = true;
                externalApp.Start();
                externalApp.WaitForExit();
                var OperatingPath = "";

                using (StreamReader reader = externalApp.StandardOutput)
                {
                    while (!reader.EndOfStream)
                    {
                        var linhaPraLer = reader.ReadLine().ToString();

                        if (linhaPraLer.Contains(@"C:\Users\"))
                        {
                            OperatingPath = $"{linhaPraLer}";
                            OperatingPath = OperatingPath.Remove(OperatingPath.Length - 1);
                        }

                        if (!linhaPraLer.Contains(@"C:\"))
                        {
                            if (CheckSize($"{OperatingPath}\\{linhaPraLer}"))
                            {
                                var path = OperatingPath + "\\" + linhaPraLer;
                                var fileHash = GetMD5(path);
                                if (!cheatsCaught.Contains(fileHash))
                                {
                                    SingleMD5(fileHash);
                                    cheatsCaught.Add(fileHash);
                                    if (path.ToLower().Contains(@"temp"))
                                    {
                                        detections.Add($"warning$$$Recently executed: {path}");
                                    }
                                    else
                                    {
                                        if (type2 == "jar")
                                        {
                                            detections.Add($"Hacked Client Found: {path}");
                                        }
                                        else
                                        {
                                            detections.Add($"warning$$${path}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (count == 7)
                {
                    stopwatch.Stop();
                    Invoke((MethodInvoker)delegate
                    {
                        int x = ((guna2Panel2.Size.Width - label1.Width) / 2) - 100;
                        int y = ((guna2Panel2.Size.Height - label1.Height) / 2) + 50;
                        scanDone.Location = new Point(x, y);
                        string minutes;
                        try
                        {
                            minutes = Convert.ToInt32(stopwatch.Elapsed.Minutes) + "m, ";

                        }
                        catch { minutes = "?m, "; }
                        string seconds;
                        try
                        {
                            seconds = Convert.ToInt32(stopwatch.Elapsed.Seconds) + "s, ";
                        }
                        catch { seconds = "?s, "; }
                        string ms;
                        try
                        {
                            ms = Convert.ToInt32(stopwatch.Elapsed.Milliseconds) + "ms";
                        }
                        catch { ms = "?ms"; }

                        scanDone.Text = "Scan complete in: " + minutes + seconds + ms;
                        guna2Panel2.Visible = true;
                    });
                    try
                    {
                        string[] files = Directory.GetFiles(tempPath + "\\analysisFolder");
                        foreach (string f in files)
                        {
                            File.Delete(f);
                        }
                        Directory.Delete(tempPath + "\\analysisFolder");
                    }
                    catch { }
                    deleteTrash();
                    sendScan();
                }
            }
            catch { }
        }

        private void ScanRecentFiles() //step 4
        {
            try
            {
                this.Invoke((MethodInvoker)delegate
                {
                    int x = (guna2Panel2.Size.Width - label1.Width) / 2;
                    int y = ((guna2Panel2.Size.Height - label1.Height) / 2) + 40;
                    label1.Location = new Point(x, y);
                    label1.Text = "Hold On! We are looking for recent files...";
                });

                progressBaar.Value = count;
                if (isTryingToBypass())
                {
                    detections.Add("Trying to bypass: Registry Cleaning");
                }

                var processo = new Process();
                processo.StartInfo.FileName = "cmd";
                processo.StartInfo.CreateNoWindow = false;
                processo.StartInfo.Arguments = $"/C " + resourceLocal + $@" /stab {tempPath}\analysis.txt";
                processo.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                processo.Start();
                processo.WaitForExit();

                Directory.CreateDirectory($@"{tempPath}\analysisFolder");
                foreach (string Line in File.ReadAllLines($@"{tempPath}\analysis.txt"))
                {
                    var atributos = Line.Split('\t');
                    var hoje = DateTime.Now;

                    try
                    {
                        var parsed2 = DateTime.Parse(atributos[1]);
                        var data = (hoje - parsed2).TotalDays;
                        if (data < 14)
                        {
                            if (CheckSize(atributos[0]))
                            {
                                File.Copy(atributos[0], $@"{tempPath}\analysisFolder\{Path.GetFileName(atributos[0])}");
                            }
                            file_activity.Add(atributos[0].ToString());
                        }
                    }
                    catch { }
                }

                UsbDebug();
                HeuristicAnalysis(heurExe, "exe");
                HeuristicAnalysis(heurJar, "jar");
                HeuristicAnalysis(heurDll, "dll");
                HeuristicAnalysis(heurJarNg, "jar");
            }
            catch { }
        }
        private void scanStrings(int ProcessoPID, string ProcessoName, string fileName) //step 2
        {

            try
            {
                getHeurs();
                count++;
                progressBaar.Maximum = 8;
                progressBaar.Value = count;
                this.Invoke((MethodInvoker)delegate
                {
                    int x = (guna2Panel2.Size.Width - label1.Width) / 2;
                    int y = ((guna2Panel2.Size.Height - label1.Height) / 2) + 40;
                    label1.Location = new Point(x, y);
                    label1.Text = "Hold On! We are scanning strings...";
                });
                var processo = new Process();
                processo.StartInfo.FileName = "cmd";
                processo.StartInfo.Arguments = $"/c {resourceLocal2} -pid {ProcessoPID} -raw -nh -l 6 > {tempPath}\\{fileName}.txt";
                processo.StartInfo.CreateNoWindow = true;
                processo.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                processo.StartInfo.RedirectStandardOutput = true;
                processo.StartInfo.UseShellExecute = false;
                processo.Start();
                string result = processo.StandardOutput.ReadToEnd();
                processo.WaitForExit();
                CheckStrings(File.ReadAllText($@"{tempPath}\{fileName}.txt"), ProcessoName);

                foreach (string Str in Form1.CustomStrings)
                {
                    if (Str.Split('$')[1] == ProcessoName)
                    {
                        if (File.ReadAllText($@"{tempPath}\{fileName}.txt").Contains(Str.Split('$')[3]))
                        {
                            detections.Add("Custom String: " + Str.Split('$')[5] + " in process: " + ProcessoName);
                        }
                    }
                }

                File.Delete(tempPath + $"\\{fileName}.txt");

                if (ProcessoName == "MsMpEng")
                {
                    ScanRecentFiles();
                }
            }
            catch (Exception e) { reportBug(e.ToString() + " At: ScanStrings()"); }
        }

        private string CompareDate(DateTime dateTime)
        {
           var result = DateTime.Now - dateTime;
           var res = Convert.ToInt32(result.TotalMinutes) + " Minutes and " + Convert.ToInt32(result.Seconds) + " seconds ago";
           return res;
        }

        private void UsbDebug()
        {
            var processo = new Process();
            processo.StartInfo.FileName = "cmd";
            processo.StartInfo.CreateNoWindow = false;
            processo.StartInfo.Arguments = $"/C " + USBDebg + $@" /stab {tempPath}\USB.txt";
            processo.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            processo.Start();
            processo.WaitForExit();
            foreach (string linha in File.ReadAllLines($@"{tempPath}\USB.txt"))
            {
                var info = linha.Split('\t');
                if(info[1].Contains("USB Mass Storage"))
                {
                    usb_letter = info[7];
                    last_usb_use = info[9];
                }
            }
            File.Delete(USBDebg);
            File.Delete($@"{tempPath}\USB.txt");
        }

        private void doMagic()
        {
            progressBaar.Maximum = File.ReadAllLines($@"{tempPath}\AnalysisFile.txt").Count();
            
            foreach (string Linha in File.ReadAllLines($@"{tempPath}\AnalysisFile.txt"))
            {
                if (!Linha.ToLower().Contains(@"temp"))
                {
                    MD5s.Add($"{GetMD5(Linha)}${Linha}");
                }
                progressBaar.Value += 1;
            }
            Process[] explorer = Process.GetProcessesByName("explorer");
            Process[] javaw = Process.GetProcessesByName("javaw");
            Process[] indexer = Process.GetProcessesByName("SearchIndexer");
            Process[] MsMpEng = Process.GetProcessesByName("MsMpEng");

            stopwatch.Start();
            
            CheckMD5();
            scanStrings(explorer[0].Id, "Explorer", generateFileName(10));
            scanStrings(GetService("DPS"), "DPS", generateFileName(9));
            scanStrings(GetService("Dnscache"), "Dnscache", generateFileName(8));
            scanStrings(GetService("DiagTrack"), "DiagTrack", generateFileName(7));
            scanStrings(GetService("PcaSvc"), "PcaSvc", generateFileName(6));
            scanStrings(indexer[0].Id, "SearchIndexer", generateFileName(6));
            scanStrings(MsMpEng[0].Id, "MsMpEng", generateFileName(7));
        }
        private void scanFiles() // Step1
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched");
            foreach (var value in key.GetValueNames())
            {
                if(value.ToLower().Contains("auto-click") || value.ToLower().Contains("autoclick"))
                {
                    detections.Add("warning:Rastros fora de uso de Generic Clicker");
                }
            }
                this.Invoke((MethodInvoker)delegate
                {
                    int x = (guna2Panel2.Size.Width - label1.Width) / 2;
                    int y = ((guna2Panel2.Size.Height - label1.Height) / 2) + 40;
                    label1.Location = new Point(x, y);
                    label1.Text = "Hold On! We are scanning files...";
                });

                var processo = new Process();
                processo.StartInfo.FileName = "cmd.exe";
                processo.StartInfo.Arguments = $"/c dir C:\\Users\\{Environment.UserName}\\Desktop C:\\Users\\{Environment.UserName}\\Downloads C:\\Users\\{Environment.UserName}\\Appdata\\Local\\Temp /s /b /a-r | findstr \".exe .jar\" > C:\\Windows\\Temp\\AnalysisFile.txt";
                processo.StartInfo.CreateNoWindow = true;
                processo.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                processo.Start();
                processo.WaitForExit();
                doMagic();
        }
        public string GetAddressString(string address)
        {
            WebClient client = new WebClient();
            string reply = client.DownloadString(address);
            return reply;
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

        private void antibypass()
        {
            if(Directory.GetFiles("C:\\Windows\\Prefetch").Count() < 40)
            {
                detections.Add("warning:Prefetch Cleaning");
            }
        }

        private void Form2_Load(object sender, EventArgs e)
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            try
            {
                antibypass();
            } catch { }
            try
            {
                var url = "";
                if (GetOSFriendlyName().Contains("7"))
                {
                    url = "http://os-scanner.site/api/GetInterface";
                }
                else
                {
                    url = "https://os-scanner.site/api/GetInterface";
                }

                var contents = GetAddressString(url);
                    JArray array = JArray.Parse(contents);
                    foreach (JObject obj in array.Children<JObject>())
                    {
                        guna2Panel1.BackColor = convertToColorArray(obj["Form2"]["panelColor"].ToString());
                        guna2Panel2.BackColor = convertToColorArray(obj["Form2"]["panelColor"].ToString());
                        progressBaar.FillColor = convertToColorArray(obj["Form2"]["progressBar1"].ToString());
                        progressBaar.ProgressColor = convertToColorArray(obj["Form2"]["progressBar2"].ToString());
                        progressBaar.ProgressColor2 = convertToColorArray(obj["Form2"]["progressBar2"].ToString());
                        pictureBox1.Image = DownloadImage(obj["Form2"]["gifUrl"].ToString());
                    }
            } catch { }

            try
            {
                File.WriteAllBytes(resourceLocal, Properties.Resources.ExecutedProgramsList);

                if (Environment.Is64BitOperatingSystem)
                {
                    File.WriteAllBytes(resourceLocal2, Properties.Resources.strings64);
                }
                else
                {
                    File.WriteAllBytes(resourceLocal2, Properties.Resources.strings32);
                }

                File.WriteAllBytes(resourceLocal3, Properties.Resources.os_dir);
                File.WriteAllBytes(USBDebg, Properties.Resources.USBDeview);
                Thread thread = new Thread(scanFiles);
                thread.Start();
            }
            catch (Exception f) { reportBug(f.ToString() + " in Main()"); }
        }
    }
}