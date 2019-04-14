using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Windows.Forms;
using ConstantsLib;

namespace NetLib
{
    public static class NetOps
    {
        public static void ReceiveFile(Socket receiver, out string fileName)
        {
            byte[] buf = new byte[Constants.BUFSIZ];

            int receivedBytesLen = receiver.Receive(buf);
            int fileNameLen = BitConverter.ToInt32(buf, 0);
            fileName = Encoding.Unicode.GetString(buf, sizeof(int), fileNameLen);
            int fileContentLen = BitConverter.ToInt32(buf, sizeof(int) + fileNameLen);

            buf = new byte[fileContentLen];

            Console.WriteLine("File {0} recieve starts.", fileName);
            if (true) //some conditions when further data getting is soficient
            {
                SendAcknowledgement(Constants.ACK_OK, receiver);
                BinaryWriter bWriter = new BinaryWriter(File.Open(fileName, FileMode.Create));
                if (fileContentLen > 0)
                {
                    receivedBytesLen = receiver.Receive(buf);
                    if (fileContentLen != receivedBytesLen)
                        throw new Exception("Miss file content");
                    bWriter.Write(buf, 0, receivedBytesLen);
                }
                Console.WriteLine("File received and saved to {0}", Path.GetDirectoryName(Application.ExecutablePath) + @"\" + fileName);
                bWriter.Close();
            }
        }

        public static void SendFile(string filePath, Socket receiver)
        {
            byte[] fileNameBytes = Encoding.Unicode.GetBytes(Path.GetFileName(filePath));
            byte[] fileNameLenBytes = BitConverter.GetBytes(fileNameBytes.Length);
            byte[] fileContent = File.ReadAllBytes(filePath);
            byte[] fileContentLen = BitConverter.GetBytes(fileContent.Length);
            byte[] sendBuf = new byte[fileContent.Length | (sizeof(int) + fileNameBytes.Length + sizeof(int))];//Marshal.SizeOf(filePath.Length)

            fileNameLenBytes.CopyTo(sendBuf, 0);
            fileNameBytes.CopyTo(sendBuf, sizeof(int));
            fileContentLen.CopyTo(sendBuf, sizeof(int) + fileNameBytes.Length);

            SendAcknowledgement(Constants.ACK_OK, receiver);
            receiver.Send(sendBuf, sizeof(int) + fileNameBytes.Length + sizeof(int), SocketFlags.None);
            if (GetAcknowlegment(receiver) == Constants.ACK_OK)
            {
                fileContent.CopyTo(sendBuf, 0);//отпрравляет сразу и служебную инфу и контент а клиент думает что это только служебная
                receiver.Send(sendBuf, fileContent.Length, SocketFlags.None);
                Console.WriteLine("File:{0} has been sent.", filePath);
            }
        }

        public static void SendAcknowledgement(int ACK, Socket receiver)
        {
            receiver.Send(BitConverter.GetBytes(ACK));
        }

        public static void SendReply(string reply, Socket receiver)
        {
            byte[] msg = Encoding.UTF8.GetBytes(reply);
            receiver.Send(msg);
        }

        public static int GetAcknowlegment(Socket receiver)
        {
            byte[] buf = new byte[sizeof(int)];
            receiver.Receive(buf, sizeof(int), SocketFlags.None);
            return BitConverter.ToInt32(buf, 0);
        }

        public static void ThrowRecievedException(Socket receiver)
        {
            byte[] buf = new byte[Constants.BUFSIZ];
            int bytesRec = receiver.Receive(buf, Constants.BUFSIZ, SocketFlags.None);
            throw new Exception(Encoding.UTF8.GetString(buf, 0, bytesRec));
        }
    }
}